import sys
import socket
import logging
import threading
import subprocess
import psutil

from utils.db import log_event
from utils.alerts import send_alert

logger = logging.getLogger(__name__)

WELL_KNOWN = {
    21: 'FTP',     22: 'SSH',      23: 'Telnet',   25: 'SMTP',
    53: 'DNS',     80: 'HTTP',    110: 'POP3',    143: 'IMAP',
    443: 'HTTPS',  445: 'SMB',    993: 'IMAPS',   995: 'POP3S',
    1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP',   5432: 'PostgreSQL',
    5900: 'VNC',  6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    8888: 'Jupyter', 27017: 'MongoDB',
}

SUSPICIOUS_PORTS = {23, 21, 5900, 3389, 1433, 6379, 27017}


def _pid_name(pid: int, cache: dict) -> str | None:
    """Look up process name for a PID, using a per-scan cache."""
    if pid in cache:
        return cache[pid]
    name = None
    try:
        if pid and pid != 0:
            name = psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
        pass
    cache[pid] = name
    return name


def _scan_windows() -> list[dict]:
    """
    Use netstat -ano on Windows — runs in a subprocess so it never touches
    the Python GIL, avoiding the freeze that psutil.net_connections() causes
    while calling Windows kernel APIs.
    """
    try:
        out = subprocess.run(
            ['netstat', '-ano'],
            capture_output=True, text=True, timeout=10
        ).stdout
    except Exception as e:
        logger.error(f"netstat scan failed: {e}")
        return []

    pid_cache: dict = {}
    seen: set = set()
    results = []

    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        proto = parts[0].upper()
        if proto not in ('TCP', 'UDP'):
            continue

        if proto == 'TCP':
            # TCP line: proto local foreign state pid
            if len(parts) < 5 or parts[3] != 'LISTENING':
                continue
            local, pid_str = parts[1], parts[4]
        else:
            # UDP line: proto local foreign pid  (no state column)
            if len(parts) < 4:
                continue
            local, pid_str = parts[1], parts[3]

        try:
            pid = int(pid_str)
        except ValueError:
            continue

        # Parse "addr:port" — works for IPv4 and [IPv6]:port
        last_colon = local.rfind(':')
        if last_colon < 0:
            continue
        try:
            port = int(local[last_colon + 1:])
        except ValueError:
            continue
        addr = local[:last_colon].strip('[]') or '0.0.0.0'

        if port >= 49152:
            continue

        key = (port, proto, addr)
        if key in seen:
            continue
        seen.add(key)

        results.append({
            'port': port,
            'protocol': proto,
            'address': addr,
            'pid': pid,
            'process_name': _pid_name(pid, pid_cache),
        })

    return sorted(results, key=lambda x: x['port'])


def _scan_psutil() -> list[dict]:
    """Use psutil on Linux/macOS — works well there with no GIL concerns."""
    seen: set = set()
    pid_cache: dict = {}
    results = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            is_tcp = conn.type == socket.SOCK_STREAM and conn.status == psutil.CONN_LISTEN
            is_udp = conn.type == socket.SOCK_DGRAM and conn.laddr and conn.laddr.port
            if not (is_tcp or is_udp):
                continue
            port = conn.laddr.port
            if port >= 49152:
                continue
            proto = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
            addr = conn.laddr.ip or '0.0.0.0'
            key = (port, proto, addr)
            if key in seen:
                continue
            seen.add(key)
            results.append({
                'port': port,
                'protocol': proto,
                'address': addr,
                'pid': conn.pid,
                'process_name': _pid_name(conn.pid or 0, pid_cache),
            })
    except psutil.AccessDenied:
        logger.warning("Port scan: access denied — some ports may be hidden")
    except Exception as e:
        logger.error(f"Port scan error: {e}")
    return sorted(results, key=lambda x: x['port'])


def _scan_listening() -> list[dict]:
    return _scan_windows() if sys.platform == 'win32' else _scan_psutil()


def _check_ports(config, is_baseline: bool = False) -> None:
    from models import get_db

    current = _scan_listening()
    current_keys = {(p['port'], p['protocol'], p['address']) for p in current}

    with get_db() as conn:
        db_open = conn.execute(
            "SELECT port, protocol, address FROM port_monitor WHERE status='OPEN'"
        ).fetchall()
        db_open_keys = {(r['port'], r['protocol'], r['address']) for r in db_open}

        for p in current:
            conn.execute(
                '''INSERT INTO port_monitor (port, protocol, address, pid, process_name, status, last_seen)
                   VALUES (?, ?, ?, ?, ?, 'OPEN', CURRENT_TIMESTAMP)
                   ON CONFLICT(port, protocol, address) DO UPDATE SET
                       pid=excluded.pid, process_name=excluded.process_name,
                       status='OPEN', last_seen=CURRENT_TIMESTAMP''',
                (p['port'], p['protocol'], p['address'], p['pid'], p['process_name'])
            )

        if not is_baseline:
            for key in db_open_keys - current_keys:
                port, proto, addr = key
                conn.execute(
                    "UPDATE port_monitor SET status='CLOSED', last_seen=CURRENT_TIMESTAMP "
                    "WHERE port=? AND protocol=? AND address=?",
                    (port, proto, addr)
                )

    if not is_baseline:
        for p in current:
            key = (p['port'], p['protocol'], p['address'])
            if key not in db_open_keys:
                service = WELL_KNOWN.get(p['port'], 'Unknown')
                flag = ' ⚠ SUSPICIOUS' if p['port'] in SUSPICIOUS_PORTS else ''
                details = (
                    f"New listening port: {p['protocol']}/{p['port']} ({service})"
                    f" on {p['address']}"
                    + (f" — {p['process_name']} (pid {p['pid']})" if p['process_name'] else "")
                    + flag
                )
                severity = 'HIGH' if p['port'] in SUSPICIOUS_PORTS else 'MEDIUM'
                log_event('NEW_PORT', severity, details=details)
                send_alert(config, 'NEW_PORT', severity, details)
                logger.warning(details)

        for key in db_open_keys - current_keys:
            port, proto, addr = key
            service = WELL_KNOWN.get(port, 'Unknown')
            details = f"Port closed: {proto}/{port} ({service}) on {addr}"
            log_event('PORT_CLOSED', 'LOW', details=details)
            logger.info(details)
    else:
        logger.info(f"Port monitor: baseline established ({len(current)} ports)")


def _loop(config, stop_event: threading.Event) -> None:
    interval = config.get('port_monitor', {}).get('interval', 30)
    stop_event.wait(3)
    try:
        from models import get_db
        with get_db() as conn:
            conn.execute("UPDATE port_monitor SET status='CLOSED' WHERE status='OPEN'")
    except Exception as e:
        logger.error(f"Port monitor startup reset: {e}")
    first = True
    while not stop_event.is_set():
        try:
            _check_ports(config, is_baseline=first)
            first = False
        except Exception as e:
            logger.error(f"Port monitor loop error: {e}")
        stop_event.wait(interval)


def start_port_monitor(config, stop_event: threading.Event) -> threading.Thread:
    t = threading.Thread(
        target=_loop, args=(config, stop_event),
        daemon=True, name='port-monitor'
    )
    t.start()
    logger.info("Port monitor started")
    return t
