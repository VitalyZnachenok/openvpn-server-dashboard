#!/usr/bin/env python3
"""
Multi-Server OpenVPN Statistics Collection and Visualization System
Supports multiple servers, multiple simultaneous sessions per user, and traffic charts.
"""

import os
import re
import sqlite3
import threading
import json
import logging
import csv
import io
import hmac
import secrets
from functools import wraps
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import time

from flask import Flask, render_template, jsonify, request, send_file, Response
from flask_cors import CORS


# All timestamps throughout the app are stored and compared in UTC.
# SQLite CURRENT_TIMESTAMP is UTC, so we normalise Python-side datetimes to
# naive UTC to keep the comparisons consistent regardless of the container TZ.
def utcnow() -> datetime:
    """Return current time as a naive UTC datetime (matches SQLite CURRENT_TIMESTAMP)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# Schema version managed via a dedicated `schema_version` table.
# Bump when the schema changes and add a migration step in DatabaseManager._migrate.
SCHEMA_VERSION = 3


def _format_chart_labels(time_slots: List[str], interval_name: str) -> List[str]:
    """Format strftime bucket keys into chart labels.

    Keeps the historical behaviour of the dashboard: short (`HH:MM`) labels
    for minute/hour intervals and ISO dates for daily buckets.
    """
    labels: List[str] = []
    for ts in time_slots:
        if not ts:
            continue
        if interval_name in ('hour', 'minute'):
            labels.append(ts.split(' ', 1)[1] if ' ' in ts else ts)
        else:
            labels.append(ts)
    return labels

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/app/data/openvpn_stats.log') if os.path.exists('/app/data') else logging.NullHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration from environment variables
DB_PATH = os.getenv("DB_PATH", "/app/data/openvpn_stats.db")
UPDATE_INTERVAL = int(os.getenv("UPDATE_INTERVAL", "60"))
FLASK_PORT = int(os.getenv("FLASK_PORT", "5000"))
FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")

# Data retention configuration
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "90"))  # Keep data for 90 days
TRAFFIC_HISTORY_RETENTION_DAYS = int(os.getenv("TRAFFIC_HISTORY_RETENTION_DAYS", "30"))  # Keep traffic snapshots for 30 days

# API configuration
DEFAULT_LIMIT = int(os.getenv("DEFAULT_LIMIT", "50"))
MAX_LIMIT = int(os.getenv("MAX_LIMIT", "500"))

# Authentication configuration
AUTH_ENABLED = os.getenv("AUTH_ENABLED", "true").lower() == "true"
AUTH_TOKEN = os.getenv("AUTH_TOKEN", "")
if AUTH_ENABLED and not AUTH_TOKEN:
    # Generate random token if not provided
    AUTH_TOKEN = secrets.token_urlsafe(32)
    logger.warning(f"⚠️  No AUTH_TOKEN provided! Generated random token: {AUTH_TOKEN}")
    logger.warning("⚠️  Set AUTH_TOKEN environment variable to use a persistent token")

# Multi-server configuration
# Format: SERVER_NAME:STATUS_FILE[:LOG_FILE]
#   - STATUS_FILE: OpenVPN status file (status-version 2)
#   - LOG_FILE   : OpenVPN main log written via `log` / `log-append`. Optional.
#                  When provided, the dashboard parses it for auth failures,
#                  disconnect reasons, TLS metrics, etc.
SERVERS_CONFIG = os.getenv("SERVERS_CONFIG", "").split(";")
SERVERS = []
for config in SERVERS_CONFIG:
    if config.strip():
        parts = config.strip().split(":")
        if len(parts) >= 2:
            log_file = parts[2] if len(parts) > 2 and parts[2] else None
            # Reject the legacy "use status file as log file" pattern: it's
            # a different file format and parsing it will produce only noise.
            if log_file and log_file == parts[1]:
                logger.warning(
                    f"[{parts[0]}] log_file equals status_file ({log_file}); "
                    f"this is almost certainly a misconfiguration — the OpenVPN "
                    f"main log (configured via `log` / `log-append`) is a "
                    f"different file. Disabling log parsing for this server."
                )
                log_file = None
            SERVERS.append({
                "name": parts[0],
                "status_file": parts[1],
                "log_file": log_file,
            })

# Fallback to single server if no multi-config
if not SERVERS:
    SERVERS = [{
        "name": "default",
        "status_file": os.getenv("OPENVPN_STATUS_FILE", "/var/log/openvpn/openvpn-status.log"),
        "log_file": os.getenv("OPENVPN_LOG_FILE") or None,
    }]

# Log-parsing toggle. When false, openvpn.log is never opened and no
# connection_events are recorded — useful in restricted environments where the
# log file isn't accessible to the container.
LOG_PARSE_ENABLED = os.getenv("LOG_PARSE_ENABLED", "true").lower() in ("1", "true", "yes", "on")

# Maximum bytes parsed per cycle from a single log file (sanity cap so a
# huge log post-rotate doesn't lock up the collector). 10 MB is enough for
# tens of thousands of events.
LOG_PARSE_MAX_BYTES = int(os.getenv("LOG_PARSE_MAX_BYTES", str(10 * 1024 * 1024)))

# Window (seconds) used to associate a parsed log event with an existing
# session row by (server, ip, port). OpenVPN log timestamps and our snapshot
# timestamps can drift by a few seconds.
LOG_EVENT_MATCH_WINDOW = int(os.getenv("LOG_EVENT_MATCH_WINDOW", "180"))

# CORS configuration
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "")

# Authentication decorator
def require_auth(f):
    """Decorator to require authentication for API endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not AUTH_ENABLED:
            return f(*args, **kwargs)
        
        # Get token from Authorization header or query parameter (for export/download links)
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.replace('Bearer ', '').strip()
        
        if not token:
            token = request.args.get('token', '').strip()
        
        if not token or not hmac.compare_digest(token, AUTH_TOKEN):
            return jsonify({'error': 'Unauthorized', 'message': 'Invalid or missing authentication token'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# Data Models
@dataclass
class VPNSession:
    username: str
    real_address: str
    real_address_port: str
    virtual_address: str
    bytes_received: int
    bytes_sent: int
    connected_since: datetime
    server_name: str
    disconnected_at: Optional[datetime] = None
    
    @property
    def duration_seconds(self) -> int:
        if self.disconnected_at:
            return int((self.disconnected_at - self.connected_since).total_seconds())
        return int((utcnow() - self.connected_since).total_seconds())
    
    @property
    def duration_formatted(self) -> str:
        seconds = self.duration_seconds
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    
    @property
    def bytes_total(self) -> int:
        return self.bytes_received + self.bytes_sent

# Enhanced Database Manager
class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.init_db()
    
    def _connect(self) -> sqlite3.Connection:
        """Create a connection with standard PRAGMA settings"""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn
    
    def init_db(self):
        with self._connect() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER NOT NULL
                )
            ''')
            row = conn.execute('SELECT version FROM schema_version').fetchone()
            current_version = row[0] if row else 0

            conn.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    server_name TEXT NOT NULL,
                    real_address TEXT NOT NULL,
                    real_address_port TEXT NOT NULL,
                    virtual_address TEXT,
                    bytes_received INTEGER DEFAULT 0,
                    bytes_sent INTEGER DEFAULT 0,
                    connected_since TIMESTAMP NOT NULL,
                    disconnected_at TIMESTAMP,
                    session_duration INTEGER,
                    disconnect_reason TEXT,
                    tls_handshake_ms INTEGER,
                    reneg_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS user_stats (
                    username TEXT NOT NULL,
                    server_name TEXT NOT NULL,
                    total_sessions INTEGER DEFAULT 0,
                    total_time_seconds INTEGER DEFAULT 0,
                    total_bytes_sent INTEGER DEFAULT 0,
                    total_bytes_received INTEGER DEFAULT 0,
                    last_seen TIMESTAMP,
                    current_status TEXT DEFAULT 'offline',
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (username, server_name)
                )
            ''')

            # traffic_history now stores only *delta* rows:
            #   - aggregate server rows: username IS NULL
            #   - per-user rows:         username IS NOT NULL
            conn.execute('''
                CREATE TABLE IF NOT EXISTS traffic_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_name TEXT NOT NULL,
                    username TEXT,
                    bytes_in INTEGER DEFAULT 0,
                    bytes_out INTEGER DEFAULT 0,
                    active_users INTEGER DEFAULT 0,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Per-session last-known counters, used to compute deltas between cycles.
            # One row per active session; rows are upserted on each snapshot and
            # removed once the session disappears from the status file.
            conn.execute('''
                CREATE TABLE IF NOT EXISTS session_traffic_state (
                    session_key TEXT PRIMARY KEY,
                    server_name TEXT NOT NULL,
                    username TEXT NOT NULL,
                    bytes_in INTEGER NOT NULL DEFAULT 0,
                    bytes_out INTEGER NOT NULL DEFAULT 0,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Append-only log of significant events parsed from openvpn.log.
            # `event_type` ∈ {auth_failure, tls_error, verify_error, disconnect,
            #                 inactivity, peer_init, reneg}.
            # `username` is best-effort: OpenVPN doesn't always include CN in
            # the failing-handshake lines.
            conn.execute('''
                CREATE TABLE IF NOT EXISTS connection_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_name TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    username TEXT,
                    real_address TEXT,
                    real_address_port TEXT,
                    reason_text TEXT,
                    raw_line TEXT,
                    timestamp TIMESTAMP NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Tracks the byte offset and inode for each parsed log file so
            # parsing is fully incremental and survives restarts. Inode change
            # or file shrink → restart from offset 0 (logrotate).
            conn.execute('''
                CREATE TABLE IF NOT EXISTS log_parse_state (
                    server_name TEXT PRIMARY KEY,
                    log_path TEXT NOT NULL,
                    inode INTEGER,
                    size INTEGER NOT NULL DEFAULT 0,
                    offset INTEGER NOT NULL DEFAULT 0,
                    last_parsed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            conn.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user_server ON sessions(username, server_name)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_sessions_disconnected_at ON sessions(disconnected_at)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_sessions_connected_since ON sessions(connected_since)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_sessions_server_disconnected ON sessions(server_name, disconnected_at)')

            for old_idx in ('idx_username', 'idx_server', 'idx_connected', 'idx_disconnected',
                            'idx_unique_active_session'):
                conn.execute(f'DROP INDEX IF EXISTS {old_idx}')

            conn.execute('''
                CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_active_session_v2
                ON sessions(username, server_name, real_address, real_address_port)
                WHERE disconnected_at IS NULL
            ''')

            conn.execute('CREATE INDEX IF NOT EXISTS idx_traffic_server_time ON traffic_history(server_name, timestamp)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_traffic_user_time ON traffic_history(username, timestamp)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_traffic_aggregate ON traffic_history(server_name, username, timestamp)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_state_server ON session_traffic_state(server_name)')

            conn.execute('CREATE INDEX IF NOT EXISTS idx_events_server_time ON connection_events(server_name, timestamp)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_events_type_time   ON connection_events(event_type, timestamp)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_events_ip_time     ON connection_events(real_address, timestamp)')

            for old_idx in ('idx_traffic_time', 'idx_traffic_server', 'idx_traffic_session_key'):
                conn.execute(f'DROP INDEX IF EXISTS {old_idx}')

            self._migrate(conn, current_version)

            conn.execute('DELETE FROM schema_version')
            conn.execute('INSERT INTO schema_version (version) VALUES (?)', (SCHEMA_VERSION,))
            conn.commit()
            logger.info(f"Database initialized at {self.db_path} (schema v{SCHEMA_VERSION})")

    def _migrate(self, conn: sqlite3.Connection, from_version: int):
        """Apply schema migrations from `from_version` up to SCHEMA_VERSION."""
        if from_version < 1:
            # v1: ensure columns added to legacy deployments exist.
            try:
                conn.execute('ALTER TABLE sessions ADD COLUMN real_address_port TEXT')
                logger.info("Migration: added real_address_port column to sessions")
            except sqlite3.OperationalError:
                pass

        if from_version < 2:
            # v2: per-session snapshots moved out of traffic_history into
            # session_traffic_state. Drop the legacy `session_key` column if it
            # still exists, and purge leftover per-session rows that used to
            # live in traffic_history (they are now represented as state rows).
            cols = {r[1] for r in conn.execute("PRAGMA table_info(traffic_history)").fetchall()}
            if 'session_key' in cols:
                removed = conn.execute(
                    "DELETE FROM traffic_history WHERE session_key IS NOT NULL"
                ).rowcount
                # SQLite supports DROP COLUMN since 3.35 (2021). Container image
                # bundles a newer one, but keep a fallback just in case.
                try:
                    conn.execute("ALTER TABLE traffic_history DROP COLUMN session_key")
                    logger.info(
                        f"Migration v2: dropped legacy session_key column, "
                        f"removed {removed} per-session rows"
                    )
                except sqlite3.OperationalError:
                    logger.info(
                        f"Migration v2: removed {removed} per-session rows "
                        f"(legacy session_key column left in place)"
                    )

        if from_version < 3:
            # v3: add openvpn.log parsing — three nullable columns on `sessions`
            # for the data we extract from the log, plus the new
            # `connection_events` and `log_parse_state` tables (created above
            # via CREATE TABLE IF NOT EXISTS).
            session_cols = {r[1] for r in conn.execute("PRAGMA table_info(sessions)").fetchall()}
            for col, ddl in (
                ('disconnect_reason', 'ALTER TABLE sessions ADD COLUMN disconnect_reason TEXT'),
                ('tls_handshake_ms',  'ALTER TABLE sessions ADD COLUMN tls_handshake_ms INTEGER'),
                ('reneg_count',       'ALTER TABLE sessions ADD COLUMN reneg_count INTEGER DEFAULT 0'),
            ):
                if col not in session_cols:
                    try:
                        conn.execute(ddl)
                        logger.info(f"Migration v3: added column sessions.{col}")
                    except sqlite3.OperationalError as e:
                        logger.warning(f"Migration v3: could not add sessions.{col}: {e}")
    
    def save_session(self, session: VPNSession):
        """Insert or update a session row.

        Handles the edge case where a client reconnects on the same
        (real_address, real_address_port) tuple before the previous session
        was marked as disconnected: OpenVPN resets byte counters to zero on a
        fresh session, so if the incoming values are lower than the stored
        ones we close the old row first and insert a new one instead of
        overwriting (and losing) the previous traffic.
        """
        with self._connect() as conn:
            existing = conn.execute('''
                SELECT id, bytes_received, bytes_sent, connected_since FROM sessions
                WHERE username = ? AND server_name = ? AND real_address = ? AND real_address_port = ?
                AND disconnected_at IS NULL
            ''', (session.username, session.server_name, session.real_address, session.real_address_port)).fetchone()

            reconnect_detected = False
            if existing and session.disconnected_at is None:
                _, old_in, old_out, _ = existing
                if session.bytes_received < old_in or session.bytes_sent < old_out:
                    reconnect_detected = True

            if reconnect_detected:
                close_ts = utcnow()
                conn.execute('''
                    UPDATE sessions SET
                        disconnected_at = ?,
                        session_duration = CAST(strftime('%s', ?) AS INTEGER) - CAST(strftime('%s', connected_since) AS INTEGER)
                    WHERE id = ?
                ''', (close_ts, close_ts, existing[0]))
                logger.info(
                    f"[{session.server_name}] Counter drop on same endpoint "
                    f"({session.real_address}:{session.real_address_port}) for "
                    f"{session.username} — closed old session id={existing[0]} "
                    f"and creating a new one"
                )
                existing = None

            if existing:
                conn.execute('''
                    UPDATE sessions SET
                        bytes_received = ?,
                        bytes_sent = ?,
                        virtual_address = ?,
                        disconnected_at = ?,
                        session_duration = ?
                    WHERE id = ?
                ''', (
                    session.bytes_received,
                    session.bytes_sent,
                    session.virtual_address,
                    session.disconnected_at,
                    session.duration_seconds if session.disconnected_at else None,
                    existing[0]
                ))
            else:
                conn.execute('''
                    INSERT INTO sessions (
                        username, server_name, real_address, real_address_port, virtual_address,
                        bytes_received, bytes_sent, connected_since,
                        disconnected_at, session_duration
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    session.username,
                    session.server_name,
                    session.real_address,
                    session.real_address_port,
                    session.virtual_address,
                    session.bytes_received,
                    session.bytes_sent,
                    session.connected_since,
                    session.disconnected_at,
                    session.duration_seconds if session.disconnected_at else None
                ))

            conn.commit()
    
    @staticmethod
    def _session_key(server_name: str, username: str, real_address: str, real_address_port: str) -> str:
        """Build a globally-unique session identifier.

        The `server_name` prefix prevents collisions when the same user
        connects from the same `ip:port` to two different servers (theoretical
        but possible behind NAT), which would otherwise mix their deltas.
        """
        return f"{server_name}|{username}|{real_address}|{real_address_port}"

    def save_traffic_snapshot(self, server_name: str, sessions: List[VPNSession]):
        """Compute traffic deltas for the current cycle and persist them.

        * Per-session cumulative counters are kept in `session_traffic_state`
          (one row per active session, upserted every cycle, removed when the
          client disappears from the OpenVPN status file).
        * Per-user delta rows (username set, non-zero traffic) are appended to
          `traffic_history` and drive the user-comparison chart.
        * An aggregate delta row (username IS NULL) is always appended and
          drives the main traffic chart.

        Freshly-connected sessions (< 2 × UPDATE_INTERVAL old) use their full
        current byte counters as the first delta, so traffic from very short
        sessions is not lost. Longer-running sessions that we have never
        observed before (e.g. after a collector restart) start from a zero
        baseline to avoid spurious spikes.
        """
        with self._connect() as conn:
            prev_rows = conn.execute('''
                SELECT session_key, bytes_in, bytes_out
                FROM session_traffic_state
                WHERE server_name = ?
            ''', (server_name,)).fetchall()
            prev_state = {r[0]: (r[1], r[2]) for r in prev_rows}

            total_delta_in = 0
            total_delta_out = 0
            active_users = len({s.username for s in sessions})

            per_user_delta: Dict[str, Tuple[int, int]] = {}
            state_upserts: List[Tuple[str, str, str, int, int]] = []
            current_keys = set()

            now = utcnow()
            fresh_threshold = UPDATE_INTERVAL * 2

            for session in sessions:
                key = self._session_key(
                    server_name, session.username, session.real_address, session.real_address_port
                )
                current_keys.add(key)
                prev = prev_state.get(key)

                if prev is not None:
                    prev_in, prev_out = prev
                    if session.bytes_received >= prev_in:
                        delta_in = session.bytes_received - prev_in
                    else:
                        delta_in = session.bytes_received
                        logger.info(
                            f"[{server_name}] Counter reset for {session.username} "
                            f"(IN: {prev_in} -> {session.bytes_received})"
                        )

                    if session.bytes_sent >= prev_out:
                        delta_out = session.bytes_sent - prev_out
                    else:
                        delta_out = session.bytes_sent
                        logger.info(
                            f"[{server_name}] Counter reset for {session.username} "
                            f"(OUT: {prev_out} -> {session.bytes_sent})"
                        )
                else:
                    session_age = (now - session.connected_since).total_seconds()
                    if 0 <= session_age < fresh_threshold:
                        delta_in = session.bytes_received
                        delta_out = session.bytes_sent
                    else:
                        delta_in = 0
                        delta_out = 0

                total_delta_in += delta_in
                total_delta_out += delta_out

                pu_in, pu_out = per_user_delta.get(session.username, (0, 0))
                per_user_delta[session.username] = (pu_in + delta_in, pu_out + delta_out)

                state_upserts.append(
                    (key, server_name, session.username, session.bytes_received, session.bytes_sent)
                )

            if state_upserts:
                conn.executemany('''
                    INSERT INTO session_traffic_state
                        (session_key, server_name, username, bytes_in, bytes_out, updated_at)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(session_key) DO UPDATE SET
                        bytes_in = excluded.bytes_in,
                        bytes_out = excluded.bytes_out,
                        username = excluded.username,
                        updated_at = CURRENT_TIMESTAMP
                ''', state_upserts)

            stale_keys = [k for k in prev_state if k not in current_keys]
            if stale_keys:
                conn.executemany(
                    'DELETE FROM session_traffic_state WHERE session_key = ?',
                    [(k,) for k in stale_keys],
                )

            user_delta_rows = [
                (server_name, username, d_in, d_out)
                for username, (d_in, d_out) in per_user_delta.items()
                if d_in > 0 or d_out > 0
            ]
            if user_delta_rows:
                conn.executemany('''
                    INSERT INTO traffic_history
                        (server_name, username, bytes_in, bytes_out, active_users)
                    VALUES (?, ?, ?, ?, 0)
                ''', user_delta_rows)

            conn.execute('''
                INSERT INTO traffic_history
                    (server_name, username, bytes_in, bytes_out, active_users)
                VALUES (?, NULL, ?, ?, ?)
            ''', (server_name, total_delta_in, total_delta_out, active_users))

            logger.debug(
                f"[{server_name}] Traffic snapshot: Δ{total_delta_in/(1024**2):.2f}MB in, "
                f"Δ{total_delta_out/(1024**2):.2f}MB out, {active_users} unique users"
            )

            conn.commit()
    
    def update_user_stats(self, username: str, server_name: str):
        with self._connect() as conn:
            now = utcnow()
            today = now.strftime('%Y-%m-%d')
            week_ago = (now - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
            
            stats = conn.execute('''
                SELECT 
                    COUNT(*) as total_sessions,
                    COALESCE(SUM(
                        CASE WHEN session_duration IS NOT NULL THEN session_duration
                        ELSE strftime('%s', 'now') - strftime('%s', connected_since)
                        END
                    ), 0) as total_time,
                    COALESCE(SUM(bytes_sent), 0) as total_sent,
                    COALESCE(SUM(bytes_received), 0) as total_received,
                    MAX(COALESCE(disconnected_at, connected_since)) as last_seen,
                    SUM(CASE WHEN disconnected_at IS NULL THEN 1 ELSE 0 END) as online_count,
                    SUM(CASE WHEN DATE(connected_since) = ? THEN 1 ELSE 0 END) as sessions_today,
                    SUM(CASE WHEN connected_since >= ? THEN 1 ELSE 0 END) as sessions_week
                FROM sessions
                WHERE username = ? AND server_name = ?
            ''', (today, week_ago, username, server_name)).fetchone()
            
            if stats and stats[0] > 0:
                conn.execute('''
                    INSERT OR REPLACE INTO user_stats (
                        username, server_name, total_sessions, total_time_seconds,
                        total_bytes_sent, total_bytes_received,
                        last_seen, current_status, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (
                    username, server_name,
                    stats[0], stats[1], stats[2], stats[3], stats[4],
                    'online' if stats[5] > 0 else 'offline'
                ))
                conn.commit()
    
    def get_active_sessions(self, server_name: Optional[str] = None) -> List[Dict]:
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            
            if server_name:
                rows = conn.execute('''
                    SELECT * FROM sessions
                    WHERE disconnected_at IS NULL AND server_name = ?
                    ORDER BY connected_since DESC
                ''', (server_name,)).fetchall()
            else:
                rows = conn.execute('''
                    SELECT * FROM sessions
                    WHERE disconnected_at IS NULL
                    ORDER BY server_name, connected_since DESC
                ''').fetchall()
            
            return [dict(row) for row in rows]
    
    def get_user_stats(self, server_name: Optional[str] = None, limit: Optional[int] = 50,
                       offset: int = 0, search: str = '') -> Tuple[List[Dict], int]:
        """Return a page of user statistics plus the total matching count.

        Pass `limit=None` to fetch every matching row (used by CSV/JSON
        exports, which must not silently truncate the dataset).
        """
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row

            now = utcnow()
            today = now.strftime('%Y-%m-%d')
            week_ago = (now - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')

            search_filter = ""
            search_params: list = []
            if search:
                search_filter = " AND us.username LIKE ?"
                search_params = [f"%{search}%"]

            if limit is None:
                limit_clause = ""
                limit_params: list = []
            else:
                limit_clause = " LIMIT ? OFFSET ?"
                limit_params = [limit, offset]

            if server_name:
                count_row = conn.execute(f'''
                    SELECT COUNT(*) FROM user_stats us
                    WHERE us.server_name = ? {search_filter}
                ''', [server_name] + search_params).fetchone()
                total_count = count_row[0] if count_row else 0

                rows = conn.execute(f'''
                    WITH session_counts AS (
                        SELECT username, server_name,
                            SUM(CASE WHEN DATE(connected_since) = ? THEN 1 ELSE 0 END) AS sessions_today,
                            SUM(CASE WHEN connected_since >= ? THEN 1 ELSE 0 END) AS sessions_week
                        FROM sessions
                        WHERE server_name = ?
                        GROUP BY username, server_name
                    )
                    SELECT
                        us.*,
                        COALESCE(sc.sessions_today, 0) AS sessions_today,
                        COALESCE(sc.sessions_week, 0) AS sessions_week
                    FROM user_stats us
                    LEFT JOIN session_counts sc
                        ON us.username = sc.username AND us.server_name = sc.server_name
                    WHERE us.server_name = ? {search_filter}
                    ORDER BY us.current_status DESC, us.last_seen DESC
                    {limit_clause}
                ''', [today, week_ago, server_name, server_name] + search_params + limit_params).fetchall()
            else:
                count_row = conn.execute(f'''
                    SELECT COUNT(DISTINCT us.username) FROM user_stats us
                    WHERE 1=1 {search_filter}
                ''', search_params).fetchone()
                total_count = count_row[0] if count_row else 0

                rows = conn.execute(f'''
                    WITH session_counts AS (
                        SELECT username,
                            SUM(CASE WHEN DATE(connected_since) = ? THEN 1 ELSE 0 END) AS sessions_today,
                            SUM(CASE WHEN connected_since >= ? THEN 1 ELSE 0 END) AS sessions_week
                        FROM sessions
                        GROUP BY username
                    )
                    SELECT
                        us.username,
                        GROUP_CONCAT(DISTINCT us.server_name) AS servers,
                        SUM(us.total_sessions) AS total_sessions,
                        SUM(us.total_time_seconds) AS total_time_seconds,
                        SUM(us.total_bytes_sent) AS total_bytes_sent,
                        SUM(us.total_bytes_received) AS total_bytes_received,
                        MAX(us.last_seen) AS last_seen,
                        MAX(us.current_status) AS current_status,
                        COALESCE(sc.sessions_today, 0) AS sessions_today,
                        COALESCE(sc.sessions_week, 0) AS sessions_week
                    FROM user_stats us
                    LEFT JOIN session_counts sc ON us.username = sc.username
                    WHERE 1=1 {search_filter}
                    GROUP BY us.username
                    ORDER BY current_status DESC, last_seen DESC
                    {limit_clause}
                ''', [today, week_ago] + search_params + limit_params).fetchall()

            return [dict(row) for row in rows], total_count
    
    def get_traffic_history(self, hours: float = 24, server_name: Optional[str] = None) -> Dict:
        """Aggregate delta traffic for the main chart (all users combined)."""
        with self._connect() as conn:
            since = utcnow() - timedelta(hours=hours)

            if hours <= 6:
                interval_format = '%Y-%m-%d %H:%M'
                interval_name = 'minute'
            elif hours <= 24:
                interval_format = '%Y-%m-%d %H:00'
                interval_name = 'hour'
            else:
                interval_format = '%Y-%m-%d'
                interval_name = 'day'

            if server_name:
                rows = conn.execute(f'''
                    SELECT
                        strftime('{interval_format}', timestamp) AS time_slot,
                        SUM(bytes_in) AS total_in,
                        SUM(bytes_out) AS total_out,
                        MAX(active_users) AS users
                    FROM traffic_history
                    WHERE timestamp > ? AND server_name = ? AND username IS NULL
                    GROUP BY time_slot
                    HAVING time_slot IS NOT NULL
                    ORDER BY time_slot
                ''', (since, server_name)).fetchall()
            else:
                rows = conn.execute(f'''
                    SELECT time_slot,
                           SUM(total_in) AS total_in,
                           SUM(total_out) AS total_out,
                           SUM(max_users) AS users
                    FROM (
                        SELECT
                            strftime('{interval_format}', timestamp) AS time_slot,
                            server_name,
                            SUM(bytes_in) AS total_in,
                            SUM(bytes_out) AS total_out,
                            MAX(active_users) AS max_users
                        FROM traffic_history
                        WHERE timestamp > ? AND username IS NULL
                        GROUP BY time_slot, server_name
                    )
                    GROUP BY time_slot
                    HAVING time_slot IS NOT NULL
                    ORDER BY time_slot
                ''', (since,)).fetchall()

            valid_rows = [row for row in rows if row[0]]
            labels = _format_chart_labels([row[0] for row in valid_rows], interval_name)

            logger.debug(
                f"Traffic history: {len(valid_rows)} data points, "
                f"server={server_name}, hours={hours}"
            )

            return {
                'labels': labels,
                'inbound': [row[1] / (1024 ** 3) if row[1] else 0 for row in valid_rows],
                'outbound': [row[2] / (1024 ** 3) if row[2] else 0 for row in valid_rows],
                'users': [int(row[3]) if row[3] else 0 for row in valid_rows],
            }
    
    def get_user_traffic_history(self, usernames: List[str], hours: float = 24,
                                  server_name: Optional[str] = None) -> Dict:
        """Per-user delta traffic for the comparison chart.

        Reads pre-computed delta rows from `traffic_history` where
        `username IS NOT NULL`, so the query is cheap and retention is
        governed by the regular `TRAFFIC_HISTORY_RETENTION_DAYS` (not the
        previous 2-hour per-session cleanup).
        """
        with self._connect() as conn:
            since = utcnow() - timedelta(hours=hours)

            if hours <= 6:
                interval_format = '%Y-%m-%d %H:%M'
                interval_name = 'minute'
            elif hours <= 24:
                interval_format = '%Y-%m-%d %H:00'
                interval_name = 'hour'
            else:
                interval_format = '%Y-%m-%d'
                interval_name = 'day'

            server_filter = " AND server_name = ?" if server_name else ""

            slots_params: list = [since]
            if server_name:
                slots_params.append(server_name)
            time_slots_query = f'''
                SELECT DISTINCT strftime('{interval_format}', timestamp) AS time_slot
                FROM traffic_history
                WHERE timestamp > ? AND username IS NOT NULL {server_filter}
                ORDER BY time_slot
            '''
            time_slots = [
                row[0] for row in conn.execute(time_slots_query, slots_params).fetchall() if row[0]
            ]
            labels = _format_chart_labels(time_slots, interval_name)

            datasets: Dict[str, Dict] = {}

            for username in usernames:
                params: list = [since, username]
                if server_name:
                    params.append(server_name)

                rows = conn.execute(f'''
                    SELECT strftime('{interval_format}', timestamp) AS time_slot,
                           COALESCE(SUM(bytes_in), 0),
                           COALESCE(SUM(bytes_out), 0)
                    FROM traffic_history
                    WHERE timestamp > ? AND username = ? {server_filter}
                    GROUP BY time_slot
                    HAVING time_slot IS NOT NULL
                ''', params).fetchall()

                deltas_by_slot = {r[0]: (r[1], r[2]) for r in rows}

                inbound = []
                outbound = []
                for ts in time_slots:
                    d_in, d_out = deltas_by_slot.get(ts, (0, 0))
                    inbound.append(d_in / (1024 ** 2))
                    outbound.append(d_out / (1024 ** 2))

                datasets[username] = {
                    'inbound': inbound,
                    'outbound': outbound,
                    'total_in_mb': sum(inbound),
                    'total_out_mb': sum(outbound),
                }

            return {
                'labels': labels,
                'datasets': datasets,
                'interval': interval_name,
            }
    
    def get_user_sessions_list(self, username: str, server_name: Optional[str] = None) -> List[Dict]:
        """Get list of sessions for a user (active and recent)"""
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            
            params = [username]
            server_filter = ""
            
            if server_name:
                server_filter = " AND server_name = ?"
                params.append(server_name)
            
            # Get active sessions
            active = conn.execute(f'''
                SELECT
                    id,
                    username,
                    server_name,
                    real_address,
                    real_address_port,
                    virtual_address,
                    bytes_received,
                    bytes_sent,
                    connected_since,
                    disconnect_reason,
                    tls_handshake_ms,
                    reneg_count,
                    'active' as status
                FROM sessions
                WHERE username = ? AND disconnected_at IS NULL {server_filter}
                ORDER BY connected_since DESC
            ''', params).fetchall()
            
            # Get recent completed sessions (last 7 days)
            week_ago = (utcnow() - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
            params_recent = [username, week_ago]
            if server_name:
                params_recent.append(server_name)
            
            recent = conn.execute(f'''
                SELECT
                    id,
                    username,
                    server_name,
                    real_address,
                    real_address_port,
                    virtual_address,
                    bytes_received,
                    bytes_sent,
                    connected_since,
                    disconnected_at,
                    disconnect_reason,
                    tls_handshake_ms,
                    reneg_count,
                    'completed' as status
                FROM sessions
                WHERE username = ? AND disconnected_at IS NOT NULL
                AND disconnected_at > ? {server_filter}
                ORDER BY disconnected_at DESC
                LIMIT 20
            ''', params_recent).fetchall()
            
            sessions = []
            for row in list(active) + list(recent):
                session = dict(row)
                session['session_key'] = self._session_key(
                    session['server_name'],
                    session['username'],
                    session['real_address'],
                    session['real_address_port'],
                )
                sessions.append(session)

            return sessions
    
    def cleanup_old_data(self, run_vacuum: bool = False):
        """Apply retention policies and keep derived aggregates consistent.

        - Sessions disconnected more than `RETENTION_DAYS` ago are removed.
        - `traffic_history` rows older than `TRAFFIC_HISTORY_RETENTION_DAYS`
          are removed.
        - Orphan rows in `session_traffic_state` (sessions we have not seen in
          multiple cycles — usually because the collector missed a cleanup
          cycle) are pruned.
        - `user_stats` is rebuilt from the surviving `sessions` so historical
          aggregates stay in sync with retention.
        - If `run_vacuum` is True, a VACUUM is executed to reclaim disk space
          from deleted rows.
        """
        try:
            with self._connect() as conn:
                sessions_cutoff = utcnow() - timedelta(days=RETENTION_DAYS)
                traffic_cutoff = utcnow() - timedelta(days=TRAFFIC_HISTORY_RETENTION_DAYS)

                sessions_deleted = conn.execute('''
                    DELETE FROM sessions
                    WHERE disconnected_at IS NOT NULL
                    AND disconnected_at < ?
                ''', (sessions_cutoff,)).rowcount

                traffic_deleted = conn.execute('''
                    DELETE FROM traffic_history
                    WHERE timestamp < ?
                ''', (traffic_cutoff,)).rowcount

                # connection_events follow the same retention as traffic
                # rows — they're event-level data with similar volume.
                events_deleted = conn.execute('''
                    DELETE FROM connection_events
                    WHERE timestamp < ?
                ''', (traffic_cutoff,)).rowcount

                # Orphan state rows: stale for more than a few update cycles.
                # Normally cleaned inline by save_traffic_snapshot, but this
                # is a safety net when the collector missed or crashed cycles.
                stale_state_cutoff = utcnow() - timedelta(seconds=max(600, UPDATE_INTERVAL * 10))
                state_deleted = conn.execute('''
                    DELETE FROM session_traffic_state
                    WHERE updated_at < ?
                ''', (stale_state_cutoff,)).rowcount

                stale_stats_deleted = conn.execute('''
                    DELETE FROM user_stats
                    WHERE (username, server_name) NOT IN (
                        SELECT DISTINCT username, server_name FROM sessions
                    )
                ''').rowcount

                if sessions_deleted > 0:
                    conn.execute('''
                        UPDATE user_stats SET
                            total_sessions = (
                                SELECT COUNT(*) FROM sessions s
                                WHERE s.username = user_stats.username
                                AND s.server_name = user_stats.server_name
                            ),
                            total_time_seconds = (
                                SELECT COALESCE(SUM(
                                    CASE WHEN s.session_duration IS NOT NULL THEN s.session_duration
                                    ELSE CAST(strftime('%s', 'now') AS INTEGER) - CAST(strftime('%s', s.connected_since) AS INTEGER)
                                    END
                                ), 0) FROM sessions s
                                WHERE s.username = user_stats.username
                                AND s.server_name = user_stats.server_name
                            ),
                            total_bytes_sent = (
                                SELECT COALESCE(SUM(s.bytes_sent), 0) FROM sessions s
                                WHERE s.username = user_stats.username
                                AND s.server_name = user_stats.server_name
                            ),
                            total_bytes_received = (
                                SELECT COALESCE(SUM(s.bytes_received), 0) FROM sessions s
                                WHERE s.username = user_stats.username
                                AND s.server_name = user_stats.server_name
                            ),
                            updated_at = CURRENT_TIMESTAMP
                    ''')

                conn.commit()

                if (sessions_deleted or traffic_deleted or events_deleted
                        or stale_stats_deleted or state_deleted):
                    logger.info(
                        f"Cleanup: removed {sessions_deleted} sessions, "
                        f"{traffic_deleted} traffic rows, "
                        f"{events_deleted} connection events, "
                        f"{state_deleted} stale state rows, "
                        f"{stale_stats_deleted} orphaned user_stats"
                    )

            if run_vacuum:
                self._run_vacuum()

            return sessions_deleted, traffic_deleted
        except Exception as e:
            logger.error(f"Error during data cleanup: {e}")
            return 0, 0

    def _run_vacuum(self):
        """VACUUM must run outside any transaction, so use a dedicated conn."""
        try:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.isolation_level = None  # autocommit
                conn.execute("VACUUM")
                logger.info("VACUUM completed")
            finally:
                conn.close()
        except Exception as e:
            logger.warning(f"VACUUM failed: {e}")

    # ---- Log-parsing helpers --------------------------------------------

    def get_log_parse_state(self, server_name: str) -> Optional[Dict]:
        """Return the persisted parser state for `server_name` or None."""
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                'SELECT * FROM log_parse_state WHERE server_name = ?',
                (server_name,),
            ).fetchone()
            return dict(row) if row else None

    def save_log_parse_state(self, server_name: str, state: Dict):
        """Upsert the parser state for `server_name`."""
        with self._connect() as conn:
            conn.execute('''
                INSERT INTO log_parse_state
                    (server_name, log_path, inode, size, offset, last_parsed_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(server_name) DO UPDATE SET
                    log_path       = excluded.log_path,
                    inode          = excluded.inode,
                    size           = excluded.size,
                    offset         = excluded.offset,
                    last_parsed_at = CURRENT_TIMESTAMP
            ''', (
                server_name,
                state.get('log_path'),
                state.get('inode'),
                state.get('size', 0),
                state.get('offset', 0),
            ))
            conn.commit()

    def save_log_events(self, events: List['LogEvent']):
        """Persist parsed events and apply their side effects to `sessions`.

        Side effects:
          * `disconnect`/`inactivity` -> set sessions.disconnect_reason
          * `peer_init` with handshake_ms -> set sessions.tls_handshake_ms
          * `reneg` -> increment sessions.reneg_count
        Side effects use a ±LOG_EVENT_MATCH_WINDOW seconds window to find
        the matching session by (server, ip, port).
        """
        if not events:
            return
        with self._connect() as conn:
            event_rows = [
                (
                    ev.server_name,
                    ev.event_type,
                    ev.username,
                    ev.real_address,
                    ev.real_address_port,
                    ev.reason_text,
                    ev.raw_line,
                    ev.timestamp,
                )
                for ev in events
            ]
            conn.executemany('''
                INSERT INTO connection_events
                    (server_name, event_type, username, real_address,
                     real_address_port, reason_text, raw_line, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', event_rows)

            window = LOG_EVENT_MATCH_WINDOW

            for ev in events:
                if not ev.real_address or not ev.real_address_port:
                    continue

                if ev.event_type in ('disconnect', 'inactivity'):
                    # Match the most recent matching session whose
                    # disconnected_at is within the time window. If none has
                    # disconnected_at yet, pick the active one — the next
                    # status snapshot will close it.
                    conn.execute('''
                        UPDATE sessions SET disconnect_reason = ?
                        WHERE id = (
                            SELECT id FROM sessions
                            WHERE server_name = ? AND real_address = ?
                              AND real_address_port = ?
                              AND disconnect_reason IS NULL
                              AND (
                                disconnected_at IS NULL
                                OR ABS(CAST(strftime('%s', disconnected_at) AS INTEGER)
                                     - CAST(strftime('%s', ?) AS INTEGER)) <= ?
                              )
                            ORDER BY connected_since DESC
                            LIMIT 1
                        )
                    ''', (
                        ev.reason_text or ev.event_type,
                        ev.server_name, ev.real_address, ev.real_address_port,
                        ev.timestamp, window,
                    ))

                elif ev.event_type == 'peer_init' and ev.extra and ev.extra.get('handshake_ms') is not None:
                    conn.execute('''
                        UPDATE sessions SET tls_handshake_ms = ?
                        WHERE id = (
                            SELECT id FROM sessions
                            WHERE server_name = ? AND real_address = ?
                              AND real_address_port = ?
                              AND tls_handshake_ms IS NULL
                              AND ABS(CAST(strftime('%s', connected_since) AS INTEGER)
                                    - CAST(strftime('%s', ?) AS INTEGER)) <= ?
                            ORDER BY ABS(CAST(strftime('%s', connected_since) AS INTEGER)
                                       - CAST(strftime('%s', ?) AS INTEGER))
                            LIMIT 1
                        )
                    ''', (
                        ev.extra['handshake_ms'],
                        ev.server_name, ev.real_address, ev.real_address_port,
                        ev.timestamp, window, ev.timestamp,
                    ))

                elif ev.event_type == 'reneg':
                    conn.execute('''
                        UPDATE sessions SET reneg_count = COALESCE(reneg_count, 0) + 1
                        WHERE id = (
                            SELECT id FROM sessions
                            WHERE server_name = ? AND real_address = ?
                              AND real_address_port = ?
                              AND disconnected_at IS NULL
                            ORDER BY connected_since DESC
                            LIMIT 1
                        )
                    ''', (ev.server_name, ev.real_address, ev.real_address_port))

            conn.commit()

    def get_auth_failures(self, server_name: Optional[str] = None,
                          hours: int = 24, limit: int = 200) -> List[Dict]:
        """Return recent auth/verify/TLS failures, newest first."""
        since = utcnow() - timedelta(hours=hours)
        params: list = ['auth_failure', 'verify_error', 'tls_error', since]
        server_filter = ''
        if server_name:
            server_filter = ' AND server_name = ?'
            params.append(server_name)
        params.append(limit)
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(f'''
                SELECT id, server_name, event_type, username,
                       real_address, real_address_port, reason_text,
                       raw_line, timestamp
                FROM connection_events
                WHERE event_type IN (?, ?, ?)
                  AND timestamp > ?
                  {server_filter}
                ORDER BY timestamp DESC
                LIMIT ?
            ''', params).fetchall()
            return [dict(r) for r in rows]

    def get_auth_failure_summary(self, server_name: Optional[str] = None,
                                  hours: int = 24) -> Dict:
        """Aggregate counters used by the dashboard summary card."""
        since = utcnow() - timedelta(hours=hours)
        params: list = ['auth_failure', 'verify_error', 'tls_error', since]
        server_filter = ''
        if server_name:
            server_filter = ' AND server_name = ?'
            params.append(server_name)
        with self._connect() as conn:
            row = conn.execute(f'''
                SELECT COUNT(*) AS total,
                       COUNT(DISTINCT real_address) AS unique_ips
                FROM connection_events
                WHERE event_type IN (?, ?, ?)
                  AND timestamp > ?
                  {server_filter}
            ''', params).fetchone()
            return {
                'total': row[0] if row else 0,
                'unique_ips': row[1] if row else 0,
                'hours': hours,
            }

    def get_recent_events(self, server_name: Optional[str] = None,
                          event_types: Optional[List[str]] = None,
                          limit: int = 100) -> List[Dict]:
        """Live tail: most-recent connection_events filtered by type/server."""
        params: list = []
        where = []
        if event_types:
            placeholders = ','.join('?' * len(event_types))
            where.append(f'event_type IN ({placeholders})')
            params.extend(event_types)
        if server_name:
            where.append('server_name = ?')
            params.append(server_name)
        where_sql = ('WHERE ' + ' AND '.join(where)) if where else ''
        params.append(limit)
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(f'''
                SELECT id, server_name, event_type, username,
                       real_address, real_address_port, reason_text,
                       raw_line, timestamp
                FROM connection_events
                {where_sql}
                ORDER BY timestamp DESC
                LIMIT ?
            ''', params).fetchall()
            return [dict(r) for r in rows]

    def get_users_list(self, server_name: Optional[str] = None) -> List[Dict]:
        """Get list of all users with online status"""
        with self._connect() as conn:
            params: list = []
            server_filter = ""
            if server_name:
                server_filter = "WHERE server_name = ?"
                params.append(server_name)
            
            rows = conn.execute(f'''
                SELECT DISTINCT username, 
                       MAX(CASE WHEN disconnected_at IS NULL THEN 1 ELSE 0 END) as is_online
                FROM sessions
                {server_filter}
                GROUP BY username
                ORDER BY is_online DESC, username
            ''', params).fetchall()
            
            return [{'username': r[0], 'is_online': bool(r[1])} for r in rows]
    
    def get_summary(self, server_name: Optional[str] = None, period: str = 'all') -> Dict:
        """Get dashboard summary statistics"""
        with self._connect() as conn:
            now = utcnow()
            today = now.strftime('%Y-%m-%d')
            server_filter = " AND server_name = ?" if server_name else ""

            summary_params: list = [today]
            if server_name:
                summary_params.append(server_name)

            row = conn.execute(f'''
                SELECT
                    COUNT(DISTINCT CASE WHEN disconnected_at IS NULL THEN username END),
                    COUNT(DISTINCT username),
                    SUM(CASE WHEN DATE(connected_since) = ? THEN 1 ELSE 0 END),
                    COUNT(DISTINCT server_name)
                FROM sessions
                WHERE 1=1 {server_filter}
            ''', summary_params).fetchone()

            traffic_period_filter = ""
            traffic_params: list = []
            if server_name:
                traffic_params.append(server_name)
            if period == 'day':
                traffic_period_filter = " AND DATE(connected_since) = ?"
                traffic_params.append(today)
            elif period in ('week', 'month'):
                days = 7 if period == 'week' else 30
                traffic_period_filter = " AND connected_since >= ?"
                traffic_params.append(
                    (now - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
                )
            
            total_traffic = conn.execute(f'''
                SELECT COALESCE(SUM(bytes_sent + bytes_received), 0)
                FROM sessions
                WHERE 1=1 {server_filter} {traffic_period_filter}
            ''', traffic_params).fetchone()[0]
            
            return {
                'active_users': row[0] or 0,
                'total_users': row[1] or 0,
                'today_sessions': row[2] or 0,
                'total_traffic': total_traffic,
                'server_count': row[3] or 0
            }

# Parser for OpenVPN status files. Supports both versions of the format:
#
#   status-version 2 (recommended, OpenVPN 2.4+ default in many distros):
#       TITLE,...
#       TIME,2026-05-14 08:21:16,1778746876
#       HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,...
#       CLIENT_LIST,alice,1.2.3.4:5000,10.8.0.10,,...,2026-05-14 07:52:19,...
#       HEADER,ROUTING_TABLE,Virtual Address,Common Name,Real Address,...
#       ROUTING_TABLE,10.8.0.10,alice,1.2.3.4:5000,...
#
#   status-version 1 (legacy default):
#       OpenVPN CLIENT LIST
#       Updated,2026-05-14 08:22:18
#       Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
#       alice,1.2.3.4:5000,12345,67890,2026-05-14 07:34:30
#       ROUTING TABLE
#       Virtual Address,Common Name,Real Address,Last Ref
#       10.8.0.10,alice,1.2.3.4:5000,2026-05-14 08:22:17
#       GLOBAL STATS
#       ...
#       END
#
# Both formats are auto-detected on every parse so a server can switch
# between them (e.g. after an OpenVPN upgrade) without restarting the
# dashboard.
class OpenVPNParser:
    # IPv6 routing-table entries (status v1 emits them) — used only to skip.
    _RE_IPV6 = re.compile(r'^[0-9a-fA-F:]+$')

    def __init__(self, status_file: str, server_name: str = "default"):
        self.status_file = status_file
        self.server_name = server_name
        self._format_logged: Optional[int] = None

    def parse_status_file(self) -> List[VPNSession]:
        if not os.path.exists(self.status_file):
            logger.warning(f"[{self.server_name}] Status file not found: {self.status_file}")
            return []

        try:
            with open(self.status_file, 'r') as f:
                lines = f.readlines()
        except IOError as e:
            logger.error(f"[{self.server_name}] I/O error reading status file: {e}")
            return []

        version = self._detect_version(lines)
        if version != self._format_logged:
            logger.info(f"[{self.server_name}] status file format detected: status-version {version}")
            self._format_logged = version

        try:
            if version == 2:
                sessions = self._parse_v2(lines)
            elif version == 1:
                sessions = self._parse_v1(lines)
            else:
                logger.warning(
                    f"[{self.server_name}] Unrecognised status file format "
                    f"(neither v1 nor v2). First non-empty line: "
                    f"{next((l.strip() for l in lines if l.strip()), '<empty>')!r}"
                )
                return []
        except Exception as e:
            logger.error(f"[{self.server_name}] Unexpected error parsing status file: {e}")
            return []

        logger.info(f"[{self.server_name}] Parsed {len(sessions)} sessions (status-version {version})")
        return sessions

    @classmethod
    def _detect_version(cls, lines: List[str]) -> Optional[int]:
        """Sniff the format from the first ~40 lines.

        v2 has explicit `TITLE,`/`HEADER,`/`CLIENT_LIST,` line prefixes.
        v1 starts with the literal banner `OpenVPN CLIENT LIST`.
        """
        for raw in lines[:40]:
            stripped = raw.strip()
            if not stripped:
                continue
            if stripped.startswith(('TITLE,', 'TIME,', 'HEADER,CLIENT_LIST', 'CLIENT_LIST,')):
                return 2
            if stripped == 'OpenVPN CLIENT LIST':
                return 1
        return None

    @staticmethod
    def _split_endpoint(endpoint: str) -> Tuple[str, str]:
        """Split `ip:port` (IPv4 or IPv6 in brackets) into (ip, port)."""
        if ':' in endpoint:
            ip, port = endpoint.rsplit(':', 1)
            return ip, port
        return endpoint, 'unknown'

    @staticmethod
    def _parse_dt(value: str) -> datetime:
        """Parse `YYYY-MM-DD HH:MM:SS` from a status file. Falls back to now."""
        try:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            return utcnow()

    # ----- status-version 2 ------------------------------------------------

    def _parse_v2(self, lines: List[str]) -> List[VPNSession]:
        sessions: List[VPNSession] = []
        routing_table: Dict[str, str] = {}

        for line_num, raw in enumerate(lines, 1):
            line = raw.strip()
            try:
                if line.startswith('CLIENT_LIST,') and not line.startswith('CLIENT_LIST,Common Name'):
                    parts = line.split(',')
                    if len(parts) < 8:
                        logger.warning(f"[{self.server_name}] Incomplete CLIENT_LIST on line {line_num}")
                        continue

                    username = parts[1]
                    ip, port = self._split_endpoint(parts[2])
                    virtual_address = parts[3] or None
                    bytes_received = int(parts[5]) if parts[5].isdigit() else 0
                    bytes_sent = int(parts[6]) if parts[6].isdigit() else 0
                    connected_since = self._parse_dt(parts[7])

                    sessions.append(VPNSession(
                        username=username,
                        real_address=ip,
                        real_address_port=port,
                        virtual_address=virtual_address,
                        bytes_received=bytes_received,
                        bytes_sent=bytes_sent,
                        connected_since=connected_since,
                        server_name=self.server_name,
                    ))

                elif line.startswith('ROUTING_TABLE,') and not line.startswith('ROUTING_TABLE,Virtual Address'):
                    parts = line.split(',')
                    if len(parts) >= 3:
                        # Skip IPv6 routes — sessions table only carries the IPv4 vIP.
                        if self._RE_IPV6.match(parts[1]) and '.' not in parts[1]:
                            continue
                        routing_table[parts[2]] = parts[1]

            except Exception as e:
                logger.error(f"[{self.server_name}] v2 parse error on line {line_num}: {e}")
                continue

        for session in sessions:
            if not session.virtual_address and session.username in routing_table:
                session.virtual_address = routing_table[session.username]

        return sessions

    # ----- status-version 1 (legacy) --------------------------------------

    # Sections we care about in v1.
    _V1_SECTIONS = {
        'OpenVPN CLIENT LIST': 'clients',
        'ROUTING TABLE': 'routes',
        'GLOBAL STATS': 'stats',
        'END': 'end',
    }

    def _parse_v1(self, lines: List[str]) -> List[VPNSession]:
        sessions: List[VPNSession] = []
        routing_table: Dict[str, str] = {}
        section: Optional[str] = None
        # Column index map for the current section's data rows. v1 header
        # ordering can differ across OpenVPN builds, so we honour the actual
        # column header line instead of assuming positions.
        client_cols: Dict[str, int] = {}
        route_cols: Dict[str, int] = {}

        # Default v1 column names (per OpenVPN docs) — fallbacks if the
        # header line is missing for some reason.
        default_client_cols = {
            'common name': 0,
            'real address': 1,
            'bytes received': 2,
            'bytes sent': 3,
            'connected since': 4,
        }
        default_route_cols = {
            'virtual address': 0,
            'common name': 1,
            'real address': 2,
            'last ref': 3,
        }

        for line_num, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line:
                continue

            new_section = self._V1_SECTIONS.get(line)
            if new_section is not None:
                section = new_section
                client_cols = {}
                route_cols = {}
                continue

            if section in (None, 'stats', 'end'):
                # We're outside any section we care about (or in GLOBAL STATS / END).
                continue

            if section == 'clients':
                if line.startswith('Updated,'):
                    continue
                lower = line.lower()
                # Header line: detect by presence of well-known column names.
                if 'common name' in lower and 'real address' in lower:
                    client_cols = {h.strip().lower(): i for i, h in enumerate(line.split(','))}
                    continue
                cols = client_cols or default_client_cols
                parts = line.split(',')
                try:
                    cn = parts[cols['common name']]
                    endpoint = parts[cols['real address']]
                    ip, port = self._split_endpoint(endpoint)
                    bytes_received = int(parts[cols['bytes received']])
                    bytes_sent = int(parts[cols['bytes sent']])
                    connected_since = self._parse_dt(parts[cols['connected since']])

                    sessions.append(VPNSession(
                        username=cn,
                        real_address=ip,
                        real_address_port=port,
                        virtual_address=None,  # backfilled from routing table below
                        bytes_received=bytes_received,
                        bytes_sent=bytes_sent,
                        connected_since=connected_since,
                        server_name=self.server_name,
                    ))
                except (KeyError, IndexError, ValueError) as e:
                    logger.warning(f"[{self.server_name}] v1 CLIENT row line {line_num}: {e}")

            elif section == 'routes':
                lower = line.lower()
                if 'virtual address' in lower and 'common name' in lower:
                    route_cols = {h.strip().lower(): i for i, h in enumerate(line.split(','))}
                    continue
                cols = route_cols or default_route_cols
                parts = line.split(',')
                try:
                    vip = parts[cols['virtual address']]
                    cn = parts[cols['common name']]
                    # Skip IPv6 entries — sessions table only stores one
                    # virtual address and the IPv4 one is usually meant.
                    if ':' in vip and '.' not in vip:
                        continue
                    routing_table[cn] = vip
                except (KeyError, IndexError):
                    continue

        for session in sessions:
            if not session.virtual_address and session.username in routing_table:
                session.virtual_address = routing_table[session.username]

        return sessions


# ---------------------------------------------------------------------------
# OpenVPN main log parser
# ---------------------------------------------------------------------------
#
# Reads `openvpn.log` (configured via `log` / `log-append` in server.conf,
# verbosity ≥ 3 recommended) and turns interesting lines into typed events.
#
# Operates incrementally: state is persisted to `log_parse_state` so the
# parser only ever reads the new bytes since the last cycle. Detects file
# rotation by comparing inode/size and restarts from offset 0 when the file
# was rotated or truncated.
#
# Event types emitted:
#   auth_failure  — bad password or pre-auth error
#   verify_error  — certificate verification failure (expired/untrusted)
#   tls_error     — TLS handshake failed for non-auth reason
#   peer_init     — successful "Peer Connection Initiated" (used to compute
#                   TLS handshake latency together with the matching
#                   "TLS: Initial packet from" line that arrived earlier)
#   reneg         — TLS soft reset (rekey) on a live session
#   disconnect    — SIGTERM/SIGINT/SIGUSR1, with the reason payload preserved
#   inactivity    — `Inactivity timeout (--ping-restart)` server-side detection

@dataclass
class LogEvent:
    event_type: str
    timestamp: datetime
    server_name: str
    username: Optional[str] = None
    real_address: Optional[str] = None
    real_address_port: Optional[str] = None
    reason_text: Optional[str] = None
    raw_line: Optional[str] = None
    extra: Optional[Dict] = None  # parser-private payload (e.g. handshake_ms)


class OpenVPNLogParser:
    # Two timestamp formats we know about:
    #   1. "Mon May 14 10:00:00 2026" — default OpenVPN `--log` output
    #   2. "2026-05-14 10:00:00"     — produced by some packagers / wrappers
    _RE_TS_LEGACY = re.compile(
        r'^(?P<ts>\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(?P<rest>.*)$'
    )
    _RE_TS_ISO = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})(?:[.,]\d+)?\s+(?P<rest>.*)$'
    )

    # Common pieces shared by multiple patterns. CN is optional because
    # pre-auth lines don't carry it; IPv4 only for now (covers > 99% of real
    # deployments). Port is part of the OpenVPN endpoint identifier.
    _IP_PORT = r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d{1,5})'
    _CN = r'(?P<cn>[A-Za-z0-9._@\-]+)'

    _PAT_AUTH_FAIL = re.compile(
        rf'(?:{_CN}/)?{_IP_PORT}\s+TLS Auth Error: (?P<reason>.+?)(?:\s+for peer)?$'
    )
    _PAT_VERIFY_ERROR = re.compile(
        rf'{_IP_PORT}\s+VERIFY ERROR: (?P<reason>.+)$'
    )
    _PAT_TLS_ERROR = re.compile(
        rf'(?:{_CN}/)?{_IP_PORT}\s+TLS Error: (?P<reason>.+)$'
    )
    _PAT_PEER_INIT = re.compile(
        rf'{_CN}/{_IP_PORT}\s+\[\S+\]\s+Peer Connection Initiated'
    )
    _PAT_TLS_INIT = re.compile(
        rf'{_IP_PORT}\s+TLS: Initial packet from'
    )
    _PAT_RENEG = re.compile(
        rf'(?:{_CN}/)?{_IP_PORT}\s+TLS: soft reset'
    )
    _PAT_SIGNAL = re.compile(
        rf'{_CN}/{_IP_PORT}\s+SIG(?P<sig>TERM|INT|USR1|HUP)\[(?P<flag>[^,\]]+),(?P<reason>[^\]]+)\]'
    )
    _PAT_INACTIVITY = re.compile(
        rf'{_CN}/{_IP_PORT}\s+\[\S+\]\s+Inactivity timeout \(--ping-restart\)'
    )
    _PAT_AUTH_USERNAME_PASSWORD_FAIL = re.compile(
        # Newer OpenVPN: explicit username on its own line
        rf'(?:{_CN}/)?{_IP_PORT}\s+PLUGIN_CALL:.*auth-user-pass.*status=1'
    )

    def __init__(self, log_file: Optional[str], server_name: str):
        self.log_file = log_file
        self.server_name = server_name
        # Pending TLS handshakes: (ip, port) -> (start_ts, raw_line). Pruned
        # when matched or after _HANDSHAKE_PRUNE_SEC. Lives in process memory
        # — losing it on restart only means we miss handshake latency for
        # in-flight handshakes, which is harmless.
        self._pending_handshakes: Dict[Tuple[str, str], datetime] = {}
        self._handshake_prune_sec = 120
        self._missing_logged = False

    @classmethod
    def _parse_timestamp(cls, line: str) -> Tuple[Optional[datetime], str]:
        """Return (timestamp, rest_of_line) or (None, line) if no timestamp."""
        m = cls._RE_TS_LEGACY.match(line)
        if m:
            try:
                # %d copes with both "5" and "05"
                ts = datetime.strptime(m.group('ts'), '%a %b %d %H:%M:%S %Y')
                return ts, m.group('rest')
            except ValueError:
                pass
        m = cls._RE_TS_ISO.match(line)
        if m:
            try:
                ts = datetime.strptime(m.group('ts'), '%Y-%m-%d %H:%M:%S')
                return ts, m.group('rest')
            except ValueError:
                pass
        return None, line

    def _prune_pending(self, now: datetime):
        cutoff = now - timedelta(seconds=self._handshake_prune_sec)
        stale = [k for k, ts in self._pending_handshakes.items() if ts < cutoff]
        for k in stale:
            self._pending_handshakes.pop(k, None)

    def parse_line(self, line: str) -> Optional[LogEvent]:
        """Recognise a single line and return a LogEvent (or None)."""
        line = line.rstrip('\n')
        if not line.strip():
            return None

        ts, rest = self._parse_timestamp(line)
        # Even if we couldn't parse the timestamp (verbose-syslog/custom
        # format) we still want to recognise the event — fall back to "now".
        ts = ts or utcnow()
        self._prune_pending(ts)

        # ---- TLS auth failure -------------------------------------------
        m = self._PAT_AUTH_FAIL.search(rest)
        if m:
            return LogEvent(
                event_type='auth_failure',
                timestamp=ts, server_name=self.server_name,
                username=m.group('cn'),
                real_address=m.group('ip'),
                real_address_port=m.group('port'),
                reason_text=m.group('reason').strip(),
                raw_line=line,
            )

        # ---- Cert verify failure ----------------------------------------
        m = self._PAT_VERIFY_ERROR.search(rest)
        if m:
            return LogEvent(
                event_type='verify_error',
                timestamp=ts, server_name=self.server_name,
                real_address=m.group('ip'),
                real_address_port=m.group('port'),
                reason_text=m.group('reason').strip(),
                raw_line=line,
            )

        # ---- TLS error (handshake failed, etc.) -------------------------
        m = self._PAT_TLS_ERROR.search(rest)
        if m:
            return LogEvent(
                event_type='tls_error',
                timestamp=ts, server_name=self.server_name,
                username=m.group('cn'),
                real_address=m.group('ip'),
                real_address_port=m.group('port'),
                reason_text=m.group('reason').strip(),
                raw_line=line,
            )

        # ---- TLS handshake start: remember the timestamp ----------------
        m = self._PAT_TLS_INIT.search(rest)
        if m:
            key = (m.group('ip'), m.group('port'))
            # Only the first packet per (ip, port) starts a handshake;
            # later retries reuse the same key, so don't overwrite to keep
            # the earliest start time.
            self._pending_handshakes.setdefault(key, ts)
            return None  # not a standalone event we record

        # ---- Peer Connection Initiated → handshake complete -------------
        m = self._PAT_PEER_INIT.search(rest)
        if m:
            key = (m.group('ip'), m.group('port'))
            start_ts = self._pending_handshakes.pop(key, None)
            handshake_ms: Optional[int] = None
            if start_ts and ts >= start_ts:
                handshake_ms = int((ts - start_ts).total_seconds() * 1000)
            return LogEvent(
                event_type='peer_init',
                timestamp=ts, server_name=self.server_name,
                username=m.group('cn'),
                real_address=m.group('ip'),
                real_address_port=m.group('port'),
                reason_text=None,
                raw_line=line,
                extra={'handshake_ms': handshake_ms} if handshake_ms is not None else None,
            )

        # ---- Renegotiation ----------------------------------------------
        m = self._PAT_RENEG.search(rest)
        if m:
            return LogEvent(
                event_type='reneg',
                timestamp=ts, server_name=self.server_name,
                username=m.group('cn'),
                real_address=m.group('ip'),
                real_address_port=m.group('port'),
                raw_line=line,
            )

        # ---- Disconnect (SIGTERM/SIGINT/SIGUSR1/SIGHUP) -----------------
        m = self._PAT_SIGNAL.search(rest)
        if m:
            return LogEvent(
                event_type='disconnect',
                timestamp=ts, server_name=self.server_name,
                username=m.group('cn'),
                real_address=m.group('ip'),
                real_address_port=m.group('port'),
                reason_text=f"SIG{m.group('sig')}[{m.group('flag')},{m.group('reason')}]",
                raw_line=line,
            )

        # ---- Inactivity timeout -----------------------------------------
        m = self._PAT_INACTIVITY.search(rest)
        if m:
            return LogEvent(
                event_type='inactivity',
                timestamp=ts, server_name=self.server_name,
                username=m.group('cn'),
                real_address=m.group('ip'),
                real_address_port=m.group('port'),
                reason_text='ping-restart',
                raw_line=line,
            )

        return None

    def parse_incremental(self, prev_state: Optional[Dict]) -> Tuple[List[LogEvent], Dict]:
        """Return (new_events, new_state).

        `prev_state` is the row from `log_parse_state` (or None on first run).
        The returned `new_state` should be persisted by the caller.
        """
        if not self.log_file:
            return [], {'log_path': None, 'inode': None, 'size': 0, 'offset': 0}

        if not os.path.exists(self.log_file):
            if not self._missing_logged:
                logger.warning(
                    f"[{self.server_name}] OpenVPN log file not found: "
                    f"{self.log_file} — log-derived features (auth failures, "
                    f"disconnect reasons, TLS metrics) will be unavailable. "
                    f"Add `log-append {self.log_file}` to your OpenVPN config."
                )
                self._missing_logged = True
            return [], {
                'log_path': self.log_file, 'inode': None, 'size': 0, 'offset': 0,
            }

        # Reset the "missing" warning latch once the file appears.
        self._missing_logged = False

        try:
            stat = os.stat(self.log_file)
        except OSError as e:
            logger.warning(f"[{self.server_name}] stat() failed on {self.log_file}: {e}")
            return [], prev_state or {
                'log_path': self.log_file, 'inode': None, 'size': 0, 'offset': 0,
            }

        prev_inode = prev_state.get('inode') if prev_state else None
        prev_offset = prev_state.get('offset', 0) if prev_state else 0

        # Detect rotation / truncation: inode changed or file shrank below
        # our last offset.
        rotated = (prev_inode is not None and prev_inode != stat.st_ino) \
            or (stat.st_size < prev_offset)
        start_offset = 0 if rotated else prev_offset

        # Cap how many bytes we read per cycle so a freshly-rotated huge
        # file doesn't stall the collector.
        bytes_to_read = stat.st_size - start_offset
        if bytes_to_read <= 0:
            return [], {
                'log_path': self.log_file,
                'inode': stat.st_ino,
                'size': stat.st_size,
                'offset': stat.st_size,
            }

        end_offset = start_offset + min(bytes_to_read, LOG_PARSE_MAX_BYTES)

        events: List[LogEvent] = []
        try:
            with open(self.log_file, 'rb') as f:
                f.seek(start_offset)
                chunk = f.read(end_offset - start_offset)
        except OSError as e:
            logger.warning(f"[{self.server_name}] read() failed on {self.log_file}: {e}")
            return [], prev_state or {
                'log_path': self.log_file, 'inode': stat.st_ino,
                'size': stat.st_size, 'offset': prev_offset,
            }

        # Trim a trailing partial line so we don't half-parse it; we'll pick
        # it up on the next cycle starting from the last newline.
        last_nl = chunk.rfind(b'\n')
        if last_nl < 0:
            # No complete line yet — wait for one to be written.
            return [], {
                'log_path': self.log_file,
                'inode': stat.st_ino,
                'size': stat.st_size,
                'offset': start_offset,
            }
        consumed = chunk[:last_nl + 1]
        new_offset = start_offset + len(consumed)

        for raw in consumed.decode('utf-8', errors='replace').splitlines():
            ev = self.parse_line(raw)
            if ev is not None:
                events.append(ev)

        if rotated:
            logger.info(
                f"[{self.server_name}] log rotation detected for "
                f"{self.log_file} — restarted parsing from offset 0"
            )

        return events, {
            'log_path': self.log_file,
            'inode': stat.st_ino,
            'size': stat.st_size,
            'offset': new_offset,
        }


# Multi-Server Stats Collector
class MultiServerStatsCollector:
    def __init__(self):
        self.db = DatabaseManager(DB_PATH)
        self.parsers = []
        for server in SERVERS:
            log_parser = None
            if LOG_PARSE_ENABLED and server.get('log_file'):
                log_parser = OpenVPNLogParser(server['log_file'], server['name'])
            self.parsers.append({
                'name': server['name'],
                'parser': OpenVPNParser(server['status_file'], server['name']),
                'log_parser': log_parser,
            })
        self.running = False
        self.cleanup_counter = 0  # cycles since last cleanup
        self.cleanup_runs = 0     # total cleanup invocations (used to schedule VACUUM)

    def collect_stats(self):
        logger.info(f"\n{'='*60}")
        logger.info(f"Collecting statistics at {utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")

        for parser_info in self.parsers:
            server_name = parser_info['name']
            parser = parser_info['parser']
            log_parser = parser_info.get('log_parser')

            logger.info(f"\n[{server_name}] Processing...")

            try:
                sessions = parser.parse_status_file()
                db_active_sessions = self.db.get_active_sessions(server_name)

                current_session_keys = {
                    (s.username, s.real_address, s.real_address_port) for s in sessions
                }

                disconnected_sessions_data = [
                    db_sess for db_sess in db_active_sessions
                    if (
                        db_sess['username'],
                        db_sess['real_address'],
                        db_sess.get('real_address_port', 'unknown'),
                    ) not in current_session_keys
                ]

                # Always take a snapshot — the state machine handles empty
                # sessions lists correctly (stale state rows will be cleared).
                self.db.save_traffic_snapshot(server_name, sessions)

                for session in sessions:
                    self.db.save_session(session)
                    self.db.update_user_stats(session.username, server_name)

                now = utcnow()
                disconnected_count = 0
                for db_session in disconnected_sessions_data:
                    disconnected_session = VPNSession(
                        username=db_session['username'],
                        real_address=db_session['real_address'],
                        real_address_port=db_session.get('real_address_port', 'unknown'),
                        virtual_address=db_session['virtual_address'],
                        bytes_received=db_session['bytes_received'],
                        bytes_sent=db_session['bytes_sent'],
                        connected_since=datetime.fromisoformat(db_session['connected_since']),
                        server_name=server_name,
                        disconnected_at=now,
                    )
                    self.db.save_session(disconnected_session)
                    self.db.update_user_stats(db_session['username'], server_name)
                    disconnected_count += 1

                # Log parsing runs *after* sessions are persisted so
                # log-derived events (disconnect_reason, handshake_ms, reneg)
                # have a row to attach to in the same cycle.
                events_count = 0
                if log_parser is not None:
                    try:
                        prev_state = self.db.get_log_parse_state(server_name)
                        events, new_state = log_parser.parse_incremental(prev_state)
                        if events:
                            self.db.save_log_events(events)
                            events_count = len(events)
                        if new_state and new_state.get('log_path'):
                            self.db.save_log_parse_state(server_name, new_state)
                    except Exception as e:
                        logger.warning(f"[{server_name}] log parse failed: {e}")

                msg = (f"[{server_name}] Updated: {len(sessions)} active, "
                       f"{disconnected_count} disconnected")
                if log_parser is not None:
                    msg += f", {events_count} log events"
                logger.info(msg)

            except Exception as e:
                logger.error(f"[{server_name}] Error processing server: {e}")
                continue

        self.cleanup_counter += 1
        cleanup_threshold = max(1, 86400 // UPDATE_INTERVAL)
        if self.cleanup_counter >= cleanup_threshold:
            self.cleanup_runs += 1
            # VACUUM roughly once a week (every 7 daily cleanups).
            run_vacuum = (self.cleanup_runs % 7 == 0)
            logger.info(
                f"Running periodic data cleanup (run #{self.cleanup_runs}, "
                f"vacuum={run_vacuum})..."
            )
            self.db.cleanup_old_data(run_vacuum=run_vacuum)
            self.cleanup_counter = 0

        logger.info(f"{'='*60}\n")
    
    def run(self):
        self.running = True
        while self.running:
            try:
                self.collect_stats()
            except Exception as e:
                logger.error(f"Error in stats collection: {e}")
            
            time.sleep(UPDATE_INTERVAL)
    
    def stop(self):
        self.running = False

# Flask Application
app = Flask(__name__)
# Only wire Flask-CORS when explicit origins are provided. With an empty list
# Flask-CORS still attaches an `Access-Control-Allow-Origin` header to every
# response, which some browsers treat as a misconfiguration on preflight. The
# app is designed to run behind the same-origin nginx in this repo, so by
# default we don't touch CORS at all.
if CORS_ORIGINS:
    CORS(app, origins=[o.strip() for o in CORS_ORIGINS.split(",") if o.strip()])

db = DatabaseManager(DB_PATH)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    """Verify authentication token"""
    if not AUTH_ENABLED:
        return jsonify({'success': True, 'message': 'Authentication disabled'})
    
    data = request.get_json() or {}
    token = data.get('token', '').strip()
    
    if hmac.compare_digest(token, AUTH_TOKEN):
        return jsonify({'success': True, 'message': 'Authentication successful'})
    else:
        return jsonify({'success': False, 'message': 'Invalid token'}), 401

@app.route('/api/check_auth')
def check_auth():
    """Check if authentication is enabled"""
    return jsonify({'auth_enabled': AUTH_ENABLED})

@app.route('/api/health')
def health():
    return jsonify({"status": "healthy", "timestamp": utcnow().isoformat() + "Z"})

@app.route('/api/servers')
@require_auth
def api_servers():
    """Get list of configured servers"""
    return jsonify([{"name": s["name"], "status_file": s["status_file"]} for s in SERVERS])

@app.route('/api/active_sessions')
@require_auth
def api_active_sessions():
    server = request.args.get('server')
    sessions = db.get_active_sessions(server)
    
    formatted_sessions = []
    now = utcnow()
    for s in sessions:
        connected_since = datetime.fromisoformat(s['connected_since'])
        duration = int((now - connected_since).total_seconds())
        hours = duration // 3600
        minutes = (duration % 3600) // 60
        secs = duration % 60
        duration_str = f"{hours:02d}:{minutes:02d}:{secs:02d}"
        
        total_bytes = s['bytes_received'] + s['bytes_sent']
        traffic_mb = round(total_bytes / (1024**2), 2)
        
        # Format real address with port
        real_addr_port = s.get('real_address_port', 'unknown')
        real_address_display = f"{s['real_address']}:{real_addr_port}" if real_addr_port != 'unknown' else s['real_address']
        
        formatted_sessions.append({
            'username': s['username'],
            'server_name': s['server_name'],
            'real_address': real_address_display,
            'virtual_address': s['virtual_address'] or 'N/A',
            'bytes_received': s['bytes_received'],
            'bytes_sent': s['bytes_sent'],
            'connected_since': s['connected_since'],
            'duration': duration_str,
            'total_traffic': f"{traffic_mb} MB",
            'download_mb': round(s['bytes_received'] / (1024**2), 2),
            'upload_mb': round(s['bytes_sent'] / (1024**2), 2)
        })
    
    return jsonify(formatted_sessions)

@app.route('/api/user_stats')
@require_auth
def api_user_stats():
    server = request.args.get('server')
    limit = min(request.args.get('limit', DEFAULT_LIMIT, type=int), MAX_LIMIT)
    offset = request.args.get('offset', 0, type=int)
    search = request.args.get('search', '').strip()
    
    try:
        stats, total_count = db.get_user_stats(server, limit, offset, search)
        
        formatted_stats = []
        for s in stats:
            total_time = s['total_time_seconds'] or 0
            hours = total_time // 3600
            minutes = (total_time % 3600) // 60
            time_str = f"{hours}h {minutes}m"
            
            bytes_sent = s['total_bytes_sent'] or 0
            bytes_received = s['total_bytes_received'] or 0
            total_bytes = bytes_sent + bytes_received
            traffic_gb = round(total_bytes / (1024**3), 2)
            
            formatted_stat = {
                'username': s['username'],
                'total_sessions': s['total_sessions'],
                'sessions_today': s.get('sessions_today', 0),
                'sessions_week': s.get('sessions_week', 0),
                'total_time': time_str,
                'total_traffic_gb': traffic_gb,
                'last_seen': s['last_seen'],
                'status': s['current_status'],
                'bytes_sent': bytes_sent,
                'bytes_received': bytes_received,
                'download_gb': round(bytes_received / (1024**3), 2),
                'upload_gb': round(bytes_sent / (1024**3), 2)
            }
            
            if 'servers' in s and s['servers']:
                formatted_stat['servers'] = s['servers']
            elif 'server_name' in s and s['server_name']:
                formatted_stat['server_name'] = s['server_name']
            
            formatted_stats.append(formatted_stat)
        
        return jsonify({
            'data': formatted_stats,
            'total': total_count,
            'limit': limit,
            'offset': offset
        })
    except Exception as e:
        logger.error(f"Error fetching user stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/traffic_chart')
@require_auth
def api_traffic_chart():
    """Get traffic chart data"""
    server = request.args.get('server')
    hours = request.args.get('hours', 24, type=float)  # Changed to float to support 0.083 (5 min)
    
    data = db.get_traffic_history(hours, server)
    return jsonify(data)

@app.route('/api/user_traffic_chart')
@require_auth
def api_user_traffic_chart():
    """Traffic chart data for a set of users (comparison mode).

    Query params:
        users:  comma-separated list of usernames (max 10)
        hours:  time window in hours (default 24)
        server: optional server filter
    """
    users_param = request.args.get('users', '')
    hours = request.args.get('hours', 24, type=float)
    server = request.args.get('server')

    if not users_param:
        return jsonify({'error': 'No users specified'}), 400

    usernames = [u.strip() for u in users_param.split(',') if u.strip()]

    if not usernames:
        return jsonify({'error': 'No valid usernames provided'}), 400

    if len(usernames) > 10:
        return jsonify({'error': 'Maximum 10 users for comparison'}), 400

    try:
        data = db.get_user_traffic_history(usernames, hours, server)
        return jsonify(data)
    except Exception as e:
        logger.error(f"Error fetching user traffic chart: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user_sessions/<username>')
@require_auth
def api_user_sessions(username):
    """Get list of sessions for a specific user"""
    server = request.args.get('server')
    
    try:
        sessions = db.get_user_sessions_list(username, server)
        
        # Format sessions for response
        formatted = []
        now = utcnow()
        for s in sessions:
            connected_since = datetime.fromisoformat(s['connected_since'])

            if s['status'] == 'active':
                duration = int((now - connected_since).total_seconds())
            else:
                disconnected_at = datetime.fromisoformat(s['disconnected_at'])
                duration = int((disconnected_at - connected_since).total_seconds())
            
            hours = duration // 3600
            minutes = (duration % 3600) // 60
            secs = duration % 60
            duration_str = f"{hours:02d}:{minutes:02d}:{secs:02d}"
            
            formatted.append({
                'id': s['id'],
                'session_key': s['session_key'],
                'server_name': s['server_name'],
                'real_address': f"{s['real_address']}:{s['real_address_port']}",
                'virtual_address': s['virtual_address'] or 'N/A',
                'bytes_received': s['bytes_received'],
                'bytes_sent': s['bytes_sent'],
                'download_mb': round(s['bytes_received'] / (1024**2), 2),
                'upload_mb': round(s['bytes_sent'] / (1024**2), 2),
                'connected_since': s['connected_since'],
                'disconnected_at': s.get('disconnected_at'),
                'duration': duration_str,
                'status': s['status'],
                # Log-derived fields (added in schema v3). They are nullable
                # — clients should treat missing values as "no log data".
                'disconnect_reason': s.get('disconnect_reason'),
                'tls_handshake_ms': s.get('tls_handshake_ms'),
                'reneg_count': s.get('reneg_count') or 0,
            })
        
        return jsonify(formatted)
    except Exception as e:
        logger.error(f"Error fetching user sessions: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users_list')
@require_auth
def api_users_list():
    """Get list of all users for dropdown selection"""
    server = request.args.get('server')
    
    try:
        return jsonify(db.get_users_list(server))
    except Exception as e:
        logger.error(f"Error fetching users list: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/summary')
@require_auth
def api_summary():
    server = request.args.get('server')
    period = request.args.get('period', 'all')
    
    summary = db.get_summary(server, period)
    traffic_gb = round(summary['total_traffic'] / (1024**3), 2)
    
    period_labels = {
        'day': 'Today',
        'week': 'Last 7 Days',
        'month': 'Last 30 Days',
        'all': 'All Time'
    }
    
    auth_failures = db.get_auth_failure_summary(server, hours=24)

    return jsonify({
        'active_users': summary['active_users'],
        'total_users': summary['total_users'],
        'today_sessions': summary['today_sessions'],
        'total_traffic_gb': traffic_gb,
        'server_count': summary['server_count'],
        'traffic_period': period,
        'traffic_period_label': period_labels.get(period, 'All Time'),
        'auth_failures_24h': auth_failures['total'],
        'auth_failure_unique_ips_24h': auth_failures['unique_ips'],
    })


@app.route('/api/auth_failures')
@require_auth
def api_auth_failures():
    """Recent auth/verify/TLS failures parsed from openvpn.log."""
    server = request.args.get('server')
    hours = max(1, min(request.args.get('hours', 24, type=int), 24 * 30))
    limit = max(1, min(request.args.get('limit', 200, type=int), 1000))
    return jsonify({
        'failures': db.get_auth_failures(server, hours, limit),
        'summary': db.get_auth_failure_summary(server, hours),
    })


@app.route('/api/recent_events')
@require_auth
def api_recent_events():
    """Live tail of connection_events. Optional filters: server, types."""
    server = request.args.get('server')
    types_param = request.args.get('types', '')
    types = [t.strip() for t in types_param.split(',') if t.strip()] or None
    limit = max(1, min(request.args.get('limit', 100, type=int), 1000))
    return jsonify({
        'events': db.get_recent_events(server, types, limit),
    })


@app.route('/api/export/sessions')
@require_auth
def export_sessions():
    """Export active sessions as CSV or JSON"""
    format_type = request.args.get('format', 'csv')
    server = request.args.get('server')
    
    try:
        sessions = db.get_active_sessions(server)
        
        if format_type == 'json':
            return jsonify(sessions)

        elif format_type == 'csv':
            # Pin a column order so automation on the consumer side can rely
            # on it instead of depending on dict iteration order.
            fieldnames = [
                'id', 'username', 'server_name',
                'real_address', 'real_address_port', 'virtual_address',
                'bytes_received', 'bytes_sent',
                'connected_since', 'disconnected_at', 'session_duration',
                'created_at',
            ]
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(sessions)

            ts = utcnow().strftime("%Y%m%d_%H%M%S")
            response = Response(output.getvalue(), mimetype='text/csv')
            response.headers['Content-Disposition'] = f'attachment; filename="vpn_sessions_{ts}.csv"'
            return response

        else:
            return jsonify({'error': 'Invalid format. Use csv or json'}), 400

    except Exception as e:
        logger.error(f"Error exporting sessions: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/users')
@require_auth
def export_users():
    """Export user statistics as CSV or JSON"""
    format_type = request.args.get('format', 'csv')
    server = request.args.get('server')
    
    try:
        # Export is allowed to return every row — otherwise users silently
        # disappear from the CSV/JSON once the table grows past MAX_LIMIT.
        stats, _ = db.get_user_stats(server, limit=None)

        export_data = []
        for s in stats:
            total_time = s['total_time_seconds'] or 0
            bytes_sent = s['total_bytes_sent'] or 0
            bytes_received = s['total_bytes_received'] or 0
            hours = total_time // 3600
            minutes = (total_time % 3600) // 60
            
            export_row = {
                'username': s['username'],
                'total_sessions': s['total_sessions'],
                'total_time_hours': hours,
                'total_time_minutes': minutes,
                'total_bytes_sent': bytes_sent,
                'total_bytes_received': bytes_received,
                'total_traffic_gb': round((bytes_sent + bytes_received) / (1024**3), 2),
                'last_seen': s['last_seen'],
                'status': s['current_status']
            }
            
            if 'servers' in s:
                export_row['servers'] = s['servers']
            elif 'server_name' in s:
                export_row['server_name'] = s['server_name']
                
            export_data.append(export_row)
        
        if format_type == 'json':
            return jsonify(export_data)
        
        elif format_type == 'csv':
            fieldnames = [
                'username', 'servers', 'server_name',
                'total_sessions', 'total_time_hours', 'total_time_minutes',
                'total_bytes_sent', 'total_bytes_received', 'total_traffic_gb',
                'last_seen', 'status',
            ]
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(export_data)

            ts = utcnow().strftime("%Y%m%d_%H%M%S")
            response = Response(output.getvalue(), mimetype='text/csv')
            response.headers['Content-Disposition'] = f'attachment; filename="vpn_users_{ts}.csv"'
            return response

        else:
            return jsonify({'error': 'Invalid format. Use csv or json'}), 400

    except Exception as e:
        logger.error(f"Error exporting user stats: {e}")
        return jsonify({'error': str(e)}), 500

def start_collector():
    """Start the background stats collector thread"""
    logger.info("Starting Multi-Server OpenVPN Statistics System")
    logger.info(f"Database: {DB_PATH}")
    logger.info(f"Update interval: {UPDATE_INTERVAL} seconds")
    logger.info(f"Data retention: {RETENTION_DAYS} days (sessions), {TRAFFIC_HISTORY_RETENTION_DAYS} days (traffic)")
    logger.info(f"Configured servers:")
    for server in SERVERS:
        logger.info(f"  - {server['name']}: {server['status_file']}")
    logger.info("="*60)
    
    collector = MultiServerStatsCollector()
    collector_thread = threading.Thread(target=collector.run, daemon=True)
    collector_thread.start()
    return collector

# Start collector on module load (works with both gunicorn and direct run)
_collector = start_collector()

if __name__ == '__main__':
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False)
