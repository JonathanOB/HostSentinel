#!/usr/bin/env python3
"""
HostSentinel Attack Simulator
==============================
Generates realistic attack events to verify every detection path:
  - SSH brute force (DB injection)
  - Honeypot HTTP (live HTTP requests to trap endpoints)
  - Honeypot SSH  (raw socket connection)
  - File integrity violation
  - New user / sudo events

Usage (server must be running):
    python simulate.py                          # defaults to localhost:5000
    python simulate.py --url http://10.0.0.1:5000 --password mypassword
    python simulate.py --no-ssh                 # skip SSH honeypot test
"""

import re
import sys
import time
import socket
import secrets
import argparse
import requests
from pathlib import Path

# Allow importing project modules when run from project root
sys.path.insert(0, str(Path(__file__).parent))

SEP  = '-' * 56
SEP2 = '=' * 56
OK   = '[OK]  '
FAIL = '[ERR] '
WARN = '[WARN]'


def _h(text):
    print(f"\n{SEP}\n  {text}\n{SEP}")


# -- HTTP honeypot -------------------------------------------------------------

def test_http_honeypot(base_url: str):
    _h("HTTP Honeypot -- scanner simulation")

    trap_paths = [
        ('/admin',        'GET'),
        ('/wp-login.php', 'GET'),
        ('/.env',         'GET'),
        ('/phpmyadmin',   'GET'),
        ('/shell',        'GET'),
        ('/.git/config',  'GET'),
        ('/xmlrpc.php',   'GET'),
    ]

    for path, method in trap_paths:
        try:
            r = requests.request(method, f"{base_url}{path}", timeout=5,
                                 headers={'User-Agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)'})
            print(f"  {OK if r.status_code in (200, 404) else WARN}  "
                  f"{method:<4} {path:<24} ->{r.status_code}")
        except Exception as e:
            print(f"  {FAIL}  {method:<4} {path:<24} ->{e}")

    # POST with fake credentials -- should be marked CREDENTIALS CAPTURED
    print()
    cred_targets = [
        ('/wp-login.php', {'log': 'admin',         'pwd': 'Password1!'}),
        ('/admin',        {'username': 'admin',     'password': 'admin123'}),
        ('/phpmyadmin',   {'pma_username': 'root',  'pma_password': 'toor'}),
    ]
    for path, creds in cred_targets:
        try:
            r = requests.post(f"{base_url}{path}", data=creds, timeout=5,
                              headers={'User-Agent': 'Mozilla/5.0 (attacker test)'})
            print(f"  {OK}  POST {path:<24} ->{r.status_code}  "
                  f"\033[33m[credentials: {list(creds.keys())}]\033[0m")
        except Exception as e:
            print(f"  {FAIL}  POST {path:<24} ->{e}")


# -- SSH honeypot --------------------------------------------------------------

def test_ssh_honeypot(host: str, port: int):
    _h(f"SSH Honeypot -- socket test (port {port})")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(12)
        s.connect((host, port))
        banner = s.recv(256)
        banner_str = banner.decode('utf-8', errors='replace').strip()
        print(f"  {OK}  Connected to {host}:{port}")
        print(f"  {OK}  Banner: {banner_str}")

        # Send a realistic SSH client version
        s.sendall(b"SSH-2.0-OpenSSH_9.3p1 Debian-1\r\n")
        time.sleep(1)

        # Send junk bytes simulating key-exchange start
        s.sendall(b"\x00\x00\x00\x1c\x0a\x14" + secrets.token_bytes(20))
        time.sleep(2)
        s.close()
        print(f"  {OK}  SSH client fingerprint sent -- check Honeypot page")
    except ConnectionRefusedError:
        print(f"  {WARN}  Port {port} refused -- honeypot may be disabled or port already in use")
    except socket.timeout:
        print(f"  {OK}  Tarpitted (connection timed out as expected)")
    except Exception as e:
        print(f"  {FAIL}  {e}")


# -- DB injection -- brute force ------------------------------------------------

def inject_brute_force(attacker_ip: str = "198.51.100.42"):
    _h(f"Brute Force Simulation ->{attacker_ip}")
    try:
        from utils.db import record_ip_attempt, count_recent_attempts, log_event
        users = ['root', 'admin', 'ubuntu', 'pi', 'deploy', 'test', 'oracle', 'postgres']
        for u in users:
            record_ip_attempt(attacker_ip, u)
        count = count_recent_attempts(attacker_ip, 120)
        print(f"  {OK}  {count} attempt records inserted")

        log_event('BRUTE_FORCE', 'CRITICAL', source_ip=attacker_ip,
                  details=f"Brute force: {count} attempts in 60s from {attacker_ip}")
        for u in users[:4]:
            log_event('FAILED_SSH', 'MEDIUM', source_ip=attacker_ip,
                      username=u,
                      details=f"Failed password for '{u}' from {attacker_ip}:44{users.index(u)+1:03d}")
        print(f"  {OK}  BRUTE_FORCE + FAILED_SSH events logged")
    except Exception as e:
        print(f"  {FAIL}  {e}")


# -- DB injection -- user / privilege events ------------------------------------

def inject_privilege_events():
    _h("Privilege Escalation / New User Simulation")
    try:
        from utils.db import log_event
        log_event('NEW_USER', 'HIGH', username='backdoor99',
                  details="New user created: 'backdoor99' (uid=1337)")
        log_event('SUDO_COMMAND', 'MEDIUM', username='www-data',
                  details="sudo by 'www-data' as root: /bin/bash")
        log_event('ROOT_LOGIN', 'HIGH', username='root',
                  details="Root console login from tty1")
        print(f"  {OK}  NEW_USER, SUDO_COMMAND, ROOT_LOGIN events logged")
    except Exception as e:
        print(f"  {FAIL}  {e}")


# -- DB injection -- file integrity ---------------------------------------------

def inject_file_change(path: str = "/etc/passwd"):
    _h(f"File Integrity Simulation ->{path}")
    try:
        from utils.db import log_event
        from models import get_db

        with get_db() as conn:
            exists = conn.execute(
                'SELECT 1 FROM file_integrity WHERE path=?', (path,)
            ).fetchone()
            if not exists:
                conn.execute(
                    "INSERT INTO file_integrity (path, hash, status) VALUES (?, ?, 'OK')",
                    (path, 'a' * 64)
                )
            conn.execute(
                "UPDATE file_integrity SET status='CHANGED', hash=? WHERE path=?",
                ('b' * 64, path)
            )

        log_event('FILE_MODIFIED', 'HIGH',
                  details=f"File integrity violation: {path}")
        print(f"  {OK}  FILE_MODIFIED event logged, integrity status ->CHANGED")
    except Exception as e:
        print(f"  {FAIL}  {e}")


# -- Dashboard stats check -----------------------------------------------------

def check_dashboard(base_url: str, password: str):
    _h("Dashboard API Check")
    sess = requests.Session()

    # Get login page to extract CSRF token
    try:
        r = sess.get(f"{base_url}/login", timeout=5)
        csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
        token = csrf.group(1) if csrf else ''

        r = sess.post(f"{base_url}/login",
                      data={"username": "admin", "password": password,
                            "csrf_token": token},
                      allow_redirects=True, timeout=5)

        if 'login' in r.url.lower():
            print(f"  {WARN}  Login failed -- check --password matches config.yaml")
        else:
            print(f"  {OK}  Logged in")
    except Exception as e:
        print(f"  {FAIL}  Login: {e}")
        return

    # Stats
    try:
        data = sess.get(f"{base_url}/api/stats", timeout=5).json()
        print(f"\n  Current stats:")
        width = max(len(k) for k in data)
        for k, v in data.items():
            bar = '#' * min(v, 30) if isinstance(v, int) else ''
            print(f"    {k:<{width}}  {v:>6}  {bar}")
    except Exception as e:
        print(f"  {FAIL}  Stats: {e}")

    # Thread status
    try:
        status = sess.get(f"{base_url}/api/status", timeout=5).json()
        print(f"\n  Thread health:")
        for name, alive in status.items():
            icon = OK if alive else WARN
            print(f"    {icon}  {name} {'running' if alive else 'NOT running'}")
    except Exception as e:
        print(f"  {FAIL}  Status: {e}")


# -- Main ----------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description='HostSentinel attack simulator')
    ap.add_argument('--url',       default='http://localhost:5000')
    ap.add_argument('--password',  default='admin')
    ap.add_argument('--host',      default='127.0.0.1', help='SSH honeypot host')
    ap.add_argument('--ssh-port',  type=int, default=2222)
    ap.add_argument('--no-ssh',    action='store_true', help='Skip SSH honeypot test')
    ap.add_argument('--no-inject', action='store_true', help='Skip DB injection tests')
    ap.add_argument('--attacker-ip', default='198.51.100.42',
                    help='Fake attacker IP for DB-injected events')
    args = ap.parse_args()

    print(f"\n{SEP2}")
    print(f"  HostSentinel Simulator")
    print(f"  Target : {args.url}")
    print(f"  SSH    : {args.host}:{args.ssh_port}")
    print(f"{SEP2}")

    test_http_honeypot(args.url)

    if not args.no_ssh:
        test_ssh_honeypot(args.host, args.ssh_port)

    if not args.no_inject:
        inject_brute_force(args.attacker_ip)
        inject_privilege_events()
        inject_file_change()

    check_dashboard(args.url, args.password)

    print(f"\n{SEP2}")
    print(f"  Done -- open {args.url} to review results")
    print(f"{SEP2}\n")


if __name__ == '__main__':
    main()
