"""
SQLite persistence layer.
Stores registered user credentials so they survive backend restarts.
"""

import sqlite3
import os

DB_PATH = os.getenv('DB_PATH', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'users.db'))


def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables on first run."""
    with get_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    UNIQUE NOT NULL,
                password_hash BLOB    NOT NULL,
                created_at    TEXT    DEFAULT (datetime('now'))
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT    NOT NULL,
                detail     TEXT,
                ip         TEXT,
                username   TEXT,
                ts         TEXT    DEFAULT (datetime('now'))
            )
        ''')
        conn.commit()
    print(f"[DB] Initialised at {DB_PATH}")


# ── User helpers ─────────────────────────────────────────────

def create_user(username: str, password_hash: bytes) -> bool:
    """Insert a new user. Returns False if username already taken."""
    try:
        with get_connection() as conn:
            conn.execute(
                'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                (username, password_hash)
            )
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def get_user(username: str) -> dict | None:
    with get_connection() as conn:
        row = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
    return dict(row) if row else None


def username_exists(username: str) -> bool:
    return get_user(username) is not None


def get_all_usernames() -> list[str]:
    with get_connection() as conn:
        rows = conn.execute('SELECT username FROM users ORDER BY created_at').fetchall()
    return [r['username'] for r in rows]


# ── Security event helpers ────────────────────────────────────

def log_security_event(event_type: str, detail: str = '', ip: str = '', username: str = ''):
    with get_connection() as conn:
        conn.execute(
            'INSERT INTO security_events (event_type, detail, ip, username) VALUES (?,?,?,?)',
            (event_type, detail, ip, username)
        )
        conn.commit()


def get_security_stats() -> dict:
    """Aggregate stats used by the dashboard."""
    with get_connection() as conn:
        total_users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        events = conn.execute('SELECT event_type, COUNT(*) as c FROM security_events GROUP BY event_type').fetchall()

    stats = {e['event_type']: e['c'] for e in events}
    return {
        'total_users': total_users,
        'login_success': stats.get('login_success', 0),
        'login_failed': stats.get('login_failed', 0),
        'account_created': stats.get('account_created', 0),
        'message_sent': stats.get('message_sent', 0),
        'message_rejected': stats.get('message_rejected', 0),
        'rate_limited': stats.get('rate_limited', 0),
        'attack_replay_blocked': stats.get('attack_replay_blocked', 0),
        # Event is logged as 'attack_tamper_blocked' by simulate_attack()
        'attack_tamper_detected': stats.get('attack_tamper_blocked', 0),
        'attack_brute_force_blocked': stats.get('attack_brute_force_blocked', 0),
        # Event is logged as 'attack_invalid_jwt_blocked' by simulate_attack()
        'attack_invalid_jwt': stats.get('attack_invalid_jwt_blocked', 0),
        'attack_mitm_blocked': stats.get('attack_mitm_blocked', 0),
        'attack_dos_blocked': stats.get('attack_dos_blocked', 0),
    }


def get_recent_security_events(limit: int = 40) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            'SELECT * FROM security_events ORDER BY id DESC LIMIT ?', (limit,)
        ).fetchall()
    return [dict(r) for r in rows]
