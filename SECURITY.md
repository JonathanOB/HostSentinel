# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in HostSentinel itself, please **do not**
open a public GitHub issue. Email the maintainer directly so the issue can be
addressed before public disclosure.

Include:
- A clear description of the vulnerability
- Steps to reproduce
- Potential impact

## Supported Versions

Only the latest commit on `main` receives security fixes.

---

## Deployment Security Checklist

### Before running on a public server

- [ ] Generate a real secret key:
  ```bash
  python3 -c "import secrets; print(secrets.token_hex(32))"
  ```
  Paste the result into `config.yaml` → `sentinel.secret_key`

- [ ] Change the dashboard password in `config.yaml` → `auth.password`

- [ ] Run behind nginx with HTTPS — use the included `nginx.conf` as a template

- [ ] Restrict dashboard access by IP in nginx (`allow`/`deny`) if not exposed publicly

- [ ] Keep port 5000 firewalled — only nginx on 443 should be public-facing:
  ```bash
  sudo ufw allow 443
  sudo ufw allow 2222   # SSH honeypot port
  sudo ufw deny 5000
  ```

### What HostSentinel does NOT do

- It does **not** block attackers at the firewall (use `ufw`/`fail2ban` for that)
- It does **not** encrypt data at rest (`data/events.db` is plaintext SQLite)
- It does **not** protect a server that is already compromised

### Data stored

HostSentinel captures and stores locally:

| Data | Location |
|---|---|
| IP addresses, timestamps, event details | `data/events.db` |
| Credentials submitted to honeypot pages | `data/events.db` → `honeypot_hits.credentials_attempted` |
| SSH client version strings | `data/events.db` → `honeypot_hits.session_data` |
| HTTP headers from scanner traffic | `data/events.db` → `honeypot_hits.headers` |

This database may contain sensitive attacker data. Protect it with appropriate
file permissions (`chmod 600 data/events.db`).
