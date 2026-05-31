"""
Honeypot module: fake SSH server + HTTP trap routes.

SSH honeypot  – listens on a decoy port, sends a realistic banner,
                captures the client's SSH version string and all raw data.
HTTP traps    – Flask routes that look like admin/login pages; capture
                every request header, query param, and POSTed credential.
"""

import time
import select
import socket
import logging
import threading
from utils.db import log_event, log_honeypot_hit
from utils.alerts import send_alert

logger = logging.getLogger(__name__)


# ── SSH Honeypot ──────────────────────────────────────────────────────────────

class SSHHoneypot:
    def __init__(self, config, event_queue):
        self.config = config
        self.event_queue = event_queue
        ssh_cfg = config['honeypot']['ssh']
        self.port = ssh_cfg['port']
        self.banner = (ssh_cfg['banner'] + '\r\n').encode()
        self.tarpit_delay = ssh_cfg.get('tarpit_delay', 2)

    def _handle(self, conn: socket.socket, addr):
        ip, port = addr
        raw = b''
        try:
            conn.settimeout(30)
            # Tarpit: slow down scanners
            time.sleep(self.tarpit_delay)
            conn.sendall(self.banner)

            # Drain everything the client sends
            while True:
                try:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
                    if len(raw) > 32768:
                        break
                except socket.timeout:
                    break
        except Exception:
            pass
        finally:
            conn.close()

        # Extract client version string (first line of SSH handshake)
        client_version = None
        if raw:
            try:
                first = raw.split(b'\n')[0].decode('utf-8', errors='replace').strip()
                if first.startswith('SSH-'):
                    client_version = first
            except Exception:
                pass

        details = f"SSH honeypot hit from {ip}:{port}"
        if client_version:
            details += f" | Client: {client_version}"

        log_honeypot_hit(
            honeypot_type='SSH',
            source_ip=ip,
            source_port=port,
            raw_data=raw[:4096].hex() if raw else None,
            session_data={
                'client_version': client_version,
                'bytes_received': len(raw),
                'our_banner': self.config['honeypot']['ssh']['banner'],
            }
        )
        log_event('HONEYPOT_SSH', 'CRITICAL', source_ip=ip, details=details)
        send_alert(self.config, 'HONEYPOT_SSH', 'CRITICAL', details, source_ip=ip)
        _enrich_async(ip, self.config)

    def run(self, stop_event: threading.Event):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(('0.0.0.0', self.port))
            sock.listen(20)
            sock.setblocking(False)
            logger.info(f"SSH honeypot on port {self.port}")

            while not stop_event.is_set():
                ready, _, _ = select.select([sock], [], [], 1.0)
                if ready:
                    try:
                        conn, addr = sock.accept()
                        threading.Thread(
                            target=self._handle, args=(conn, addr), daemon=True
                        ).start()
                    except Exception as e:
                        logger.error(f"SSH honeypot accept: {e}")
        except OSError as e:
            logger.error(f"SSH honeypot bind failed on port {self.port}: {e}")
        finally:
            sock.close()


# ── HTTP Traps ────────────────────────────────────────────────────────────────

_FAKE_LOGIN = '''<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font:14px Arial,sans-serif;background:#f4f4f4;display:flex;
     justify-content:center;align-items:center;height:100vh}
.box{background:#fff;padding:30px;border-radius:4px;
     box-shadow:0 2px 8px rgba(0,0,0,.15);width:340px}
h2{text-align:center;margin-bottom:20px;color:#333}
input{width:100%;padding:10px;margin:6px 0 14px;
      border:1px solid #ccc;border-radius:3px;font-size:14px}
button{width:100%;padding:11px;background:#0073aa;color:#fff;
       border:none;border-radius:3px;font-size:15px;cursor:pointer}
button:hover{background:#005f8b}
.err{color:#c00;text-align:center;margin-top:10px;font-size:13px}
</style></head>
<body><div class="box">
<h2>Administrator Login</h2>
<form method="POST">
<input name="username" placeholder="Username" required autocomplete="off">
<input name="password" type="password" placeholder="Password" required>
<button type="submit">Sign In</button>
<p class="err">Incorrect username or password.</p>
</form></div></body></html>'''

_FAKE_404 = ('<!DOCTYPE html><html><head><title>404</title></head>'
             '<body><h1>Not Found</h1></body></html>')


def build_http_traps(config, event_queue) -> list:
    from flask import request, render_template_string

    traps = []
    trap_paths = config['honeypot']['http'].get('trap_paths', [])

    def _make_handler(trap_path: str):
        def _handler():
            ip = (request.headers.get('X-Forwarded-For', request.remote_addr) or '')
            ip = ip.split(',')[0].strip()

            headers_dict = dict(request.headers)
            credentials = None

            if request.method == 'POST':
                cred = {}
                for key in ('username', 'user', 'login', 'email',
                            'password', 'pass', 'passwd', 'pwd'):
                    val = request.form.get(key)
                    if val:
                        cred[key] = val
                if not cred and request.is_json:
                    body = request.get_json(silent=True) or {}
                    for key in ('username', 'user', 'login', 'email',
                                'password', 'pass', 'passwd'):
                        if key in body:
                            cred[key] = body[key]
                if cred:
                    credentials = cred

            log_honeypot_hit(
                honeypot_type='HTTP',
                source_ip=ip,
                headers=headers_dict,
                user_agent=request.headers.get('User-Agent'),
                path=trap_path,
                method=request.method,
                credentials=credentials,
                session_data={
                    'query': request.query_string.decode(errors='replace'),
                    'body': request.get_data(as_text=True)[:500],
                    'referrer': request.headers.get('Referer'),
                }
            )

            severity = 'CRITICAL' if credentials else 'HIGH'
            details = (
                f"HTTP honeypot: {request.method} {trap_path} from {ip}"
                + (f" | Credentials: {list(credentials.keys())}" if credentials else "")
            )

            log_event('HONEYPOT_HTTP', severity, source_ip=ip, details=details)
            send_alert(config, 'HONEYPOT_HTTP', severity, details, source_ip=ip)
            _enrich_async(ip, config)

            login_paths = ('/admin', '/wp-admin', '/wp-login.php',
                           '/phpmyadmin', '/login')
            if trap_path in login_paths or request.method == 'POST':
                return render_template_string(_FAKE_LOGIN), 200
            return _FAKE_404, 404

        _handler.__name__ = f'hp_{trap_path.strip("/").replace("/", "_") or "root"}'
        return _handler

    for path in trap_paths:
        traps.append((path, _make_handler(path)))

    return traps


# ── Helpers ───────────────────────────────────────────────────────────────────

def _enrich_async(ip: str, config):
    def _run():
        try:
            from utils.intelligence import get_ip_intel
            from utils.db import update_attacker_intel
            intel = get_ip_intel(ip, config)
            if intel:
                update_attacker_intel(ip, intel)
        except Exception as e:
            logger.error(f"Honeypot intel enrichment {ip}: {e}")
    threading.Thread(target=_run, daemon=True).start()


def start_honeypots(config, stop_event, event_queue) -> list:
    threads = []
    if config['honeypot']['ssh']['enabled']:
        hp = SSHHoneypot(config, event_queue)
        t = threading.Thread(
            target=hp.run, args=(stop_event,),
            daemon=True, name='ssh-honeypot'
        )
        t.start()
        threads.append(t)
    logger.info("Honeypots started")
    return threads
