import os
import sqlite3
from contextlib import contextmanager
from config import get_config


def get_db_path():
    return get_config()['database']['path']


@contextmanager
def get_db():
    db_path = get_db_path()
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_type  TEXT NOT NULL,
                severity    TEXT NOT NULL,
                source_ip   TEXT,
                username    TEXT,
                details     TEXT,
                raw_log     TEXT,
                acknowledged INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS attackers (
                ip              TEXT PRIMARY KEY,
                first_seen      DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen       DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_count     INTEGER DEFAULT 0,
                country         TEXT,
                country_code    TEXT,
                city            TEXT,
                org             TEXT,
                hostname        TEXT,
                whois_summary   TEXT,
                is_blocked      INTEGER DEFAULT 0,
                threat_score    INTEGER DEFAULT 0,
                notes           TEXT
            );

            CREATE TABLE IF NOT EXISTS honeypot_hits (
                id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp               DATETIME DEFAULT CURRENT_TIMESTAMP,
                honeypot_type           TEXT NOT NULL,
                source_ip               TEXT,
                source_port             INTEGER,
                raw_data                TEXT,
                headers                 TEXT,
                user_agent              TEXT,
                path                    TEXT,
                method                  TEXT,
                credentials_attempted   TEXT,
                session_data            TEXT
            );

            CREATE TABLE IF NOT EXISTS file_integrity (
                path                TEXT PRIMARY KEY,
                hash                TEXT NOT NULL,
                size                INTEGER,
                last_checked        DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_known_modified DATETIME,
                baseline_established DATETIME DEFAULT CURRENT_TIMESTAMP,
                status              TEXT DEFAULT 'OK'
            );

            CREATE TABLE IF NOT EXISTS ip_attempts (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ip        TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                username  TEXT,
                method    TEXT DEFAULT 'password'
            );

            CREATE TABLE IF NOT EXISTS port_monitor (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                port         INTEGER NOT NULL,
                protocol     TEXT NOT NULL,
                address      TEXT NOT NULL,
                pid          INTEGER,
                process_name TEXT,
                status       TEXT DEFAULT 'OPEN',
                first_seen   DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen    DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(port, protocol, address)
            );

            CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_events_type     ON events(event_type);
            CREATE INDEX IF NOT EXISTS idx_events_ip       ON events(source_ip);
            CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
            CREATE INDEX IF NOT EXISTS idx_attempts_ip_ts  ON ip_attempts(ip, timestamp);
            CREATE INDEX IF NOT EXISTS idx_honeypot_ip     ON honeypot_hits(source_ip);
            CREATE INDEX IF NOT EXISTS idx_honeypot_ts     ON honeypot_hits(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_port_status     ON port_monitor(status);
        ''')
