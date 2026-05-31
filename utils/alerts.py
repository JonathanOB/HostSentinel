import smtplib
import logging
import threading
import requests
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    'INFO':     0x6e7681,
    'LOW':      0x58a6ff,
    'MEDIUM':   0xe3b341,
    'HIGH':     0xfd7e14,
    'CRITICAL': 0xda3633,
}
SEVERITY_EMOJI = {
    'INFO': 'ℹ️',  'LOW': '🔵',
    'MEDIUM': '🟡', 'HIGH': '🟠', 'CRITICAL': '🚨',
}


def send_alert(config, event_type, severity, details,
               source_ip=None, extra: dict = None):
    cfg = config.get('alerts', {})
    if not (cfg.get('email', {}).get('enabled') or cfg.get('discord', {}).get('enabled')):
        return

    def _dispatch():
        if cfg.get('email', {}).get('enabled'):
            try:
                _send_email(cfg['email'], event_type, severity, details, source_ip)
            except Exception as e:
                logger.error(f"Email alert failed: {e}")
        if cfg.get('discord', {}).get('enabled'):
            try:
                _send_discord(cfg['discord'], event_type, severity, details, source_ip, extra)
            except Exception as e:
                logger.error(f"Discord alert failed: {e}")

    threading.Thread(target=_dispatch, daemon=True).start()


def _send_email(cfg, event_type, severity, details, source_ip):
    msg = MIMEMultipart()
    msg['From'] = cfg['from_addr']
    msg['To'] = cfg['to_addr']
    msg['Subject'] = f"[HostSentinel] {severity} – {event_type}"
    body = (
        f"HostSentinel Security Alert\n"
        f"{'=' * 40}\n"
        f"Time:       {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"Event Type: {event_type}\n"
        f"Severity:   {severity}\n"
        f"Source IP:  {source_ip or 'N/A'}\n\n"
        f"Details:\n{details}\n"
    )
    msg.attach(MIMEText(body, 'plain'))
    with smtplib.SMTP(cfg['smtp_host'], cfg['smtp_port']) as s:
        s.starttls()
        s.login(cfg['username'], cfg['password'])
        s.sendmail(cfg['from_addr'], cfg['to_addr'], msg.as_string())
    logger.info(f"Email alert sent: {event_type}")


def _send_discord(cfg, event_type, severity, details, source_ip, extra):
    emoji = SEVERITY_EMOJI.get(severity, '⚠️')
    fields = [
        {"name": "Event",    "value": event_type, "inline": True},
        {"name": "Severity", "value": f"{emoji} {severity}", "inline": True},
        {"name": "Time",
         "value": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
         "inline": True},
    ]
    if source_ip:
        fields.append({"name": "Source IP", "value": f"`{source_ip}`", "inline": True})
    if extra:
        for k, v in extra.items():
            fields.append({"name": k, "value": str(v)[:1024], "inline": False})

    payload = {"embeds": [{
        "title": f"{emoji} HostSentinel: {event_type}",
        "description": details[:2048],
        "color": SEVERITY_COLORS.get(severity, 0x95a5a6),
        "fields": fields,
        "footer": {"text": "HostSentinel IDS"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }]}
    r = requests.post(cfg['webhook_url'], json=payload, timeout=10)
    r.raise_for_status()
    logger.info(f"Discord alert sent: {event_type}")
