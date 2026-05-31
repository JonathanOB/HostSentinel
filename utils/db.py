import json
import logging
from datetime import datetime, timedelta
from models import get_db

logger = logging.getLogger(__name__)

_event_queue = None


def set_event_queue(q) -> None:
    global _event_queue
    _event_queue = q


def _push_to_queue(evt: dict) -> None:
    if _event_queue is None:
        return
    try:
        _event_queue.put_nowait(evt)
    except Exception:
        pass


def log_event(event_type, severity, source_ip=None, username=None,
              details=None, raw_log=None):
    try:
        with get_db() as conn:
            conn.execute(
                '''INSERT INTO events
                   (event_type, severity, source_ip, username, details, raw_log)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (event_type, severity, source_ip, username, details, raw_log)
            )
        if source_ip:
            _touch_attacker(source_ip)
        _push_to_queue({
            'type': 'event',
            'event_type': event_type,
            'severity': severity,
            'source_ip': source_ip,
            'details': details,
            'timestamp': datetime.utcnow().isoformat(),
        })
    except Exception as e:
        logger.error(f"log_event failed: {e}")


def log_honeypot_hit(honeypot_type, source_ip, source_port=None, raw_data=None,
                     headers=None, user_agent=None, path=None, method=None,
                     credentials=None, session_data=None):
    try:
        with get_db() as conn:
            conn.execute(
                '''INSERT INTO honeypot_hits
                   (honeypot_type, source_ip, source_port, raw_data, headers,
                    user_agent, path, method, credentials_attempted, session_data)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (honeypot_type, source_ip, source_port, raw_data,
                 json.dumps(headers) if headers else None,
                 user_agent, path, method,
                 json.dumps(credentials) if credentials else None,
                 json.dumps(session_data) if session_data else None)
            )
        if source_ip:
            _touch_attacker(source_ip)
    except Exception as e:
        logger.error(f"log_honeypot_hit failed: {e}")


def record_ip_attempt(ip, username=None, method='password'):
    try:
        with get_db() as conn:
            conn.execute(
                'INSERT INTO ip_attempts (ip, username, method) VALUES (?, ?, ?)',
                (ip, username, method)
            )
    except Exception as e:
        logger.error(f"record_ip_attempt failed: {e}")


def count_recent_attempts(ip, window_seconds=60):
    # SQLite CURRENT_TIMESTAMP uses space separator; isoformat() uses 'T' — must match
    cutoff = (datetime.utcnow() - timedelta(seconds=window_seconds)).strftime('%Y-%m-%d %H:%M:%S')
    try:
        with get_db() as conn:
            row = conn.execute(
                'SELECT COUNT(*) FROM ip_attempts WHERE ip=? AND timestamp>?',
                (ip, cutoff)
            ).fetchone()
        return row[0] if row else 0
    except Exception as e:
        logger.error(f"count_recent_attempts failed: {e}")
        return 0


def _touch_attacker(ip):
    try:
        with get_db() as conn:
            exists = conn.execute(
                'SELECT 1 FROM attackers WHERE ip=?', (ip,)
            ).fetchone()
            if exists:
                conn.execute(
                    '''UPDATE attackers
                       SET last_seen=CURRENT_TIMESTAMP, event_count=event_count+1
                       WHERE ip=?''',
                    (ip,)
                )
            else:
                conn.execute(
                    'INSERT INTO attackers (ip, event_count) VALUES (?, 1)',
                    (ip,)
                )
    except Exception as e:
        logger.error(f"_touch_attacker failed for {ip}: {e}")


def update_attacker_intel(ip, data: dict):
    try:
        with get_db() as conn:
            conn.execute(
                '''UPDATE attackers
                   SET country=?, country_code=?, city=?, org=?,
                       hostname=?, whois_summary=?, threat_score=?
                   WHERE ip=?''',
                (data.get('country'), data.get('country_code'),
                 data.get('city'), data.get('org'),
                 data.get('hostname'), data.get('whois_summary'),
                 data.get('threat_score', 0), ip)
            )
    except Exception as e:
        logger.error(f"update_attacker_intel failed for {ip}: {e}")


def get_recent_events(limit=50, offset=0, event_type=None, severity=None, ip=None):
    conds, params = [], []
    if event_type:
        conds.append('event_type=?'); params.append(event_type)
    if severity:
        conds.append('severity=?'); params.append(severity)
    if ip:
        conds.append('source_ip=?'); params.append(ip)
    where = ('WHERE ' + ' AND '.join(conds)) if conds else ''
    try:
        with get_db() as conn:
            rows = conn.execute(
                f'SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?',
                params + [limit, offset]
            ).fetchall()
            total = conn.execute(
                f'SELECT COUNT(*) FROM events {where}', params
            ).fetchone()[0]
        return [dict(r) for r in rows], total
    except Exception as e:
        logger.error(f"get_recent_events failed: {e}")
        return [], 0


def get_dashboard_stats():
    today = datetime.utcnow().date().isoformat()
    try:
        with get_db() as conn:
            return {
                'total_events': conn.execute('SELECT COUNT(*) FROM events').fetchone()[0],
                'events_today': conn.execute(
                    "SELECT COUNT(*) FROM events WHERE date(timestamp)=?", (today,)
                ).fetchone()[0],
                'brute_force_today': conn.execute(
                    "SELECT COUNT(*) FROM events WHERE event_type='BRUTE_FORCE' AND date(timestamp)=?",
                    (today,)
                ).fetchone()[0],
                'honeypot_today': conn.execute(
                    "SELECT COUNT(*) FROM honeypot_hits WHERE date(timestamp)=?", (today,)
                ).fetchone()[0],
                'unique_attackers': conn.execute(
                    'SELECT COUNT(DISTINCT ip) FROM attackers'
                ).fetchone()[0],
                'critical_unacked': conn.execute(
                    "SELECT COUNT(*) FROM events WHERE severity='CRITICAL' AND acknowledged=0"
                ).fetchone()[0],
                'file_changes': conn.execute(
                    "SELECT COUNT(*) FROM events WHERE event_type='FILE_MODIFIED'"
                ).fetchone()[0],
                'honeypot_total': conn.execute(
                    'SELECT COUNT(*) FROM honeypot_hits'
                ).fetchone()[0],
            }
    except Exception as e:
        logger.error(f"get_dashboard_stats failed: {e}")
        return {}


def get_events_chart_data(hours=24):
    cutoff = (datetime.utcnow() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
    try:
        with get_db() as conn:
            rows = conn.execute(
                '''SELECT strftime('%Y-%m-%d %H:00:00', timestamp) AS hour,
                          event_type, COUNT(*) AS count
                   FROM events WHERE timestamp > ?
                   GROUP BY hour, event_type ORDER BY hour''',
                (cutoff,)
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"get_events_chart_data failed: {e}")
        return []


def get_top_attackers(limit=10):
    try:
        with get_db() as conn:
            rows = conn.execute(
                'SELECT * FROM attackers ORDER BY event_count DESC LIMIT ?', (limit,)
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"get_top_attackers failed: {e}")
        return []


def get_attacker(ip):
    try:
        with get_db() as conn:
            row = conn.execute('SELECT * FROM attackers WHERE ip=?', (ip,)).fetchone()
        return dict(row) if row else None
    except Exception as e:
        logger.error(f"get_attacker failed: {e}")
        return None


def get_honeypot_hits(limit=50, offset=0, honeypot_type=None, ip=None):
    conds, params = [], []
    if honeypot_type:
        conds.append('honeypot_type=?'); params.append(honeypot_type)
    if ip:
        conds.append('source_ip=?'); params.append(ip)
    where = ('WHERE ' + ' AND '.join(conds)) if conds else ''
    try:
        with get_db() as conn:
            rows = conn.execute(
                f'SELECT * FROM honeypot_hits {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?',
                params + [limit, offset]
            ).fetchall()
            total = conn.execute(
                f'SELECT COUNT(*) FROM honeypot_hits {where}', params
            ).fetchone()[0]
        return [dict(r) for r in rows], total
    except Exception as e:
        logger.error(f"get_honeypot_hits failed: {e}")
        return [], 0


def get_file_integrity_status():
    try:
        with get_db() as conn:
            rows = conn.execute(
                'SELECT * FROM file_integrity ORDER BY path'
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"get_file_integrity_status failed: {e}")
        return []


def acknowledge_event(event_id):
    try:
        with get_db() as conn:
            conn.execute('UPDATE events SET acknowledged=1 WHERE id=?', (event_id,))
    except Exception as e:
        logger.error(f"acknowledge_event failed: {e}")


def get_honeypot_stats():
    try:
        with get_db() as conn:
            rows = conn.execute(
                '''SELECT honeypot_type, COUNT(*) as count,
                          COUNT(DISTINCT source_ip) as unique_ips
                   FROM honeypot_hits GROUP BY honeypot_type'''
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"get_honeypot_stats failed: {e}")
        return []


def get_record_counts() -> dict:
    try:
        with get_db() as conn:
            return {
                'events':       conn.execute('SELECT COUNT(*) FROM events').fetchone()[0],
                'attackers':    conn.execute('SELECT COUNT(*) FROM attackers').fetchone()[0],
                'honeypot_hits':conn.execute('SELECT COUNT(*) FROM honeypot_hits').fetchone()[0],
                'ip_attempts':  conn.execute('SELECT COUNT(*) FROM ip_attempts').fetchone()[0],
                'integrity':    conn.execute('SELECT COUNT(*) FROM file_integrity').fetchone()[0],
                'ports':        conn.execute("SELECT COUNT(*) FROM port_monitor WHERE status='OPEN'").fetchone()[0],
            }
    except Exception as e:
        logger.error(f"get_record_counts failed: {e}")
        return {}


def reset_database() -> None:
    with get_db() as conn:
        conn.executescript('''
            DELETE FROM events;
            DELETE FROM attackers;
            DELETE FROM honeypot_hits;
            DELETE FROM ip_attempts;
            DELETE FROM file_integrity;
            DELETE FROM port_monitor;
        ''')
        conn.execute(
            "DELETE FROM sqlite_sequence WHERE name IN "
            "('events', 'honeypot_hits', 'ip_attempts', 'port_monitor')"
        )
    from utils.intelligence import _cache as _intel_cache
    _intel_cache.clear()
    logger.info("Database reset: all tables cleared")


# ── Port monitor ──────────────────────────────────────────────────────────────

def upsert_port(port: int, protocol: str, address: str,
                pid: int = None, process_name: str = None) -> None:
    try:
        with get_db() as conn:
            conn.execute(
                '''INSERT INTO port_monitor (port, protocol, address, pid, process_name, status, last_seen)
                   VALUES (?, ?, ?, ?, ?, 'OPEN', CURRENT_TIMESTAMP)
                   ON CONFLICT(port, protocol, address) DO UPDATE SET
                       pid=excluded.pid,
                       process_name=excluded.process_name,
                       status='OPEN',
                       last_seen=CURRENT_TIMESTAMP''',
                (port, protocol, address, pid, process_name)
            )
    except Exception as e:
        logger.error(f"upsert_port failed: {e}")


def mark_port_closed(port: int, protocol: str, address: str) -> None:
    try:
        with get_db() as conn:
            conn.execute(
                "UPDATE port_monitor SET status='CLOSED', last_seen=CURRENT_TIMESTAMP "
                "WHERE port=? AND protocol=? AND address=?",
                (port, protocol, address)
            )
    except Exception as e:
        logger.error(f"mark_port_closed failed: {e}")


def get_all_ports() -> list:
    try:
        with get_db() as conn:
            rows = conn.execute(
                "SELECT * FROM port_monitor ORDER BY status DESC, port ASC"
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"get_all_ports failed: {e}")
        return []
