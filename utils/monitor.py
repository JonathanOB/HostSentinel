import os
import time
import hashlib
import logging
import threading
import subprocess
from datetime import datetime

from utils.parser import parse_auth_line
from utils.db import (log_event, record_ip_attempt, count_recent_attempts,
                      update_attacker_intel)
from utils.alerts import send_alert
from models import get_db

logger = logging.getLogger(__name__)

_brute_alerted: set = set()
_brute_lock = threading.Lock()


# ── File Integrity ────────────────────────────────────────────────────────────

def _sha256(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except PermissionError:
        return 'PERMISSION_DENIED'
    except FileNotFoundError:
        return 'NOT_FOUND'
    except Exception as e:
        logger.error(f"Hash error for {path}: {e}")
        return 'ERROR'


def _establish_baselines(paths: list[str]):
    with get_db() as conn:
        for path in paths:
            existing = conn.execute(
                'SELECT 1 FROM file_integrity WHERE path=?', (path,)
            ).fetchone()
            if existing:
                continue
            hash_val = _sha256(path)
            try:
                mtime = datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
                size = os.path.getsize(path)
            except Exception:
                mtime = size = None
            conn.execute(
                '''INSERT INTO file_integrity (path, hash, size, last_known_modified, status)
                   VALUES (?, ?, ?, ?, 'OK')''',
                (path, hash_val, size, mtime)
            )
            logger.info(f"Baseline: {path} -> {hash_val[:12]}")


def _file_integrity_loop(config, event_queue, stop_event):
    paths = config['monitoring'].get('watched_files', [])
    _establish_baselines(paths)

    while not stop_event.is_set():
        for path in paths:
            current = _sha256(path)
            if current in ('PERMISSION_DENIED', 'NOT_FOUND', 'ERROR'):
                continue
            try:
                with get_db() as conn:
                    row = conn.execute(
                        'SELECT hash FROM file_integrity WHERE path=?', (path,)
                    ).fetchone()
                    if row and row['hash'] != current:
                        details = f"File integrity violation: {path}"
                        log_event('FILE_MODIFIED', 'HIGH', details=details, raw_log=path)
                        send_alert(config, 'FILE_MODIFIED', 'HIGH', details)
                        conn.execute(
                            "UPDATE file_integrity SET hash=?, status='CHANGED', "
                            "last_checked=CURRENT_TIMESTAMP WHERE path=?",
                            (current, path)
                        )
                        logger.warning(f"File changed: {path}")
                    elif row:
                        conn.execute(
                            'UPDATE file_integrity SET last_checked=CURRENT_TIMESTAMP WHERE path=?',
                            (path,)
                        )
            except Exception as e:
                logger.error(f"Integrity check error {path}: {e}")

        stop_event.wait(30)


# ── SSH Log Monitor ───────────────────────────────────────────────────────────

def _process_event(event: dict, config, event_queue):
    if not event:
        return

    source_ip = event.get('source_ip')
    event_type = event['event_type']
    severity = event['severity']

    if event_type == 'FAILED_SSH' and source_ip:
        record_ip_attempt(source_ip, event.get('username'))
        threshold = config['monitoring'].get('brute_force_threshold', 6)
        window = config['monitoring'].get('brute_force_window', 60)
        count = count_recent_attempts(source_ip, window)

        with _brute_lock:
            already_alerted = source_ip in _brute_alerted

        if count >= threshold and not already_alerted:
            with _brute_lock:
                _brute_alerted.add(source_ip)
            details = (
                f"Brute force from {source_ip}: "
                f"{count} attempts in {window}s"
            )
            log_event('BRUTE_FORCE', 'CRITICAL', source_ip=source_ip, details=details)
            send_alert(config, 'BRUTE_FORCE', 'CRITICAL', details, source_ip)
            _enrich_async(source_ip, config)

        elif count < threshold:
            with _brute_lock:
                _brute_alerted.discard(source_ip)

    log_event(
        event_type, severity,
        source_ip=source_ip,
        username=event.get('username'),
        details=event.get('details'),
        raw_log=event.get('raw_log'),
    )

    if source_ip and severity in ('HIGH', 'CRITICAL'):
        _enrich_async(source_ip, config)


def _enrich_async(ip: str, config):
    def _run():
        try:
            from utils.intelligence import get_ip_intel
            intel = get_ip_intel(ip, config)
            if intel:
                update_attacker_intel(ip, intel)
        except Exception as e:
            logger.error(f"Intel enrichment failed {ip}: {e}")
    threading.Thread(target=_run, daemon=True).start()


def _tail_auth_log(config, event_queue, stop_event):
    log_path = config['monitoring'].get('auth_log', '/var/log/auth.log')
    if not os.path.exists(log_path):
        logger.info(f"{log_path} not found — falling back to journalctl")
        _tail_journalctl(config, event_queue, stop_event)
        return

    logger.info(f"Monitoring {log_path}")
    try:
        proc = subprocess.Popen(
            ['tail', '-F', '-n', '0', log_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        while not stop_event.is_set():
            line = proc.stdout.readline()
            if line:
                ev = parse_auth_line(line)
                if ev:
                    _process_event(ev, config, event_queue)
            elif proc.poll() is not None:
                logger.warning("tail process died — restarting in 5s")
                time.sleep(5)
                _tail_auth_log(config, event_queue, stop_event)
                return
    except Exception as e:
        logger.error(f"Auth log monitor error: {e}")
        time.sleep(5)


def _tail_journalctl(config, event_queue, stop_event):
    logger.info("Monitoring via journalctl -u sshd")
    try:
        proc = subprocess.Popen(
            ['journalctl', '-f', '-n', '0', '-u', 'sshd', '--no-pager'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        while not stop_event.is_set():
            line = proc.stdout.readline()
            if line:
                ev = parse_auth_line(line)
                if ev:
                    _process_event(ev, config, event_queue)
    except FileNotFoundError:
        logger.warning("journalctl not found — SSH auth log monitoring inactive on this platform")
    except Exception as e:
        logger.warning(f"journalctl monitor error: {e}")


def start_monitoring(config, stop_event, event_queue) -> list:
    threads = []

    t1 = threading.Thread(
        target=_tail_auth_log,
        args=(config, event_queue, stop_event),
        daemon=True, name='auth-monitor'
    )
    t1.start()
    threads.append(t1)

    t2 = threading.Thread(
        target=_file_integrity_loop,
        args=(config, event_queue, stop_event),
        daemon=True, name='file-integrity'
    )
    t2.start()
    threads.append(t2)

    logger.info("Monitoring threads started")
    return threads
