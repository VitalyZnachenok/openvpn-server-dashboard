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
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import time

from flask import Flask, render_template, jsonify, request, send_file, Response
from flask_cors import CORS

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

# Multi-server configuration
# Format: SERVER_NAME:STATUS_FILE:LOG_FILE
SERVERS_CONFIG = os.getenv("SERVERS_CONFIG", "").split(";")
SERVERS = []
for config in SERVERS_CONFIG:
    if config.strip():
        parts = config.strip().split(":")
        if len(parts) >= 2:
            SERVERS.append({
                "name": parts[0],
                "status_file": parts[1],
                "log_file": parts[2] if len(parts) > 2 else None
            })

# Fallback to single server if no multi-config
if not SERVERS:
    SERVERS = [{
        "name": "default",
        "status_file": os.getenv("OPENVPN_STATUS_FILE", "/var/log/openvpn/openvpn-status.log"),
        "log_file": os.getenv("OPENVPN_LOG_FILE", "/var/log/openvpn/openvpn.log")
    }]

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
        return int((datetime.now() - self.connected_since).total_seconds())
    
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
    
    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            
            # Enhanced sessions table with server_name
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
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Add real_address_port column if it doesn't exist (migration for existing databases)
            try:
                conn.execute('ALTER TABLE sessions ADD COLUMN real_address_port TEXT')
                logger.info("Added real_address_port column to sessions table")
            except sqlite3.OperationalError:
                # Column already exists
                pass
            
            conn.execute('CREATE INDEX IF NOT EXISTS idx_username ON sessions(username)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_server ON sessions(server_name)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_connected ON sessions(connected_since)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_disconnected ON sessions(disconnected_at)')
            
            # Drop old unique index if exists
            try:
                conn.execute('DROP INDEX IF EXISTS idx_unique_active_session')
            except sqlite3.OperationalError:
                pass
            
            # Create unique index to prevent duplicate active sessions
            # Unique key: username + server + real_address + port (allows multiple sessions from same user on different devices/ports)
            conn.execute('''
                CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_active_session_v2
                ON sessions(username, server_name, real_address, real_address_port)
                WHERE disconnected_at IS NULL
            ''')
            
            # Enhanced user stats with server info
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
            
            # Traffic history table for charts
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
            
            conn.execute('CREATE INDEX IF NOT EXISTS idx_traffic_time ON traffic_history(timestamp)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_traffic_server ON traffic_history(server_name)')
            
            conn.commit()
            logger.info(f"Database initialized at {self.db_path}")
    
    def save_session(self, session: VPNSession):
        with sqlite3.connect(self.db_path) as conn:
            # Check existing session by unique key (username, server, real_address, port)
            existing = conn.execute('''
                SELECT id FROM sessions 
                WHERE username = ? AND server_name = ? AND real_address = ? AND real_address_port = ?
                AND disconnected_at IS NULL
            ''', (session.username, session.server_name, session.real_address, session.real_address_port)).fetchone()
            
            if existing:
                # Update existing session
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
                # Insert new session
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
    
    def save_traffic_snapshot(self, server_name: str, sessions: List[VPNSession]):
        """Save traffic snapshot for charts (delta from previous snapshot)"""
        with sqlite3.connect(self.db_path) as conn:
            prev_sessions = {}
            
            # Fetch previous session states
            last_timestamp_query = conn.execute('''
                SELECT MAX(timestamp) FROM traffic_history 
                WHERE server_name = ? AND username IS NOT NULL
            ''', (server_name,)).fetchone()
            
            if last_timestamp_query and last_timestamp_query[0]:
                last_timestamp = last_timestamp_query[0]
                prev_data = conn.execute('''
                    SELECT username, bytes_in, bytes_out, timestamp
                    FROM traffic_history
                    WHERE server_name = ? AND username IS NOT NULL AND timestamp = ?
                ''', (server_name, last_timestamp)).fetchall()
                
                for row in prev_data:
                    username = row[0]
                    if username not in prev_sessions:
                        prev_sessions[username] = []
                    prev_sessions[username].append({
                        'bytes_in': row[1],
                        'bytes_out': row[2]
                    })
            
            total_delta_in = 0
            total_delta_out = 0
            active_users = len(set(s.username for s in sessions))
            
            current_sessions_by_user = {}
            for session in sessions:
                if session.username not in current_sessions_by_user:
                    current_sessions_by_user[session.username] = []
                current_sessions_by_user[session.username].append(session)
            
            for username, user_sessions in current_sessions_by_user.items():
                prev_user_sessions = prev_sessions.get(username, [])
                
                current_user_in = sum(s.bytes_received for s in user_sessions)
                current_user_out = sum(s.bytes_sent for s in user_sessions)
                
                prev_user_in = sum(p['bytes_in'] for p in prev_user_sessions)
                prev_user_out = sum(p['bytes_out'] for p in prev_user_sessions)
                
                if prev_user_sessions:
                    if current_user_in >= prev_user_in:
                        user_delta_in = current_user_in - prev_user_in
                    else:
                        user_delta_in = current_user_in
                        logger.info(f"[{server_name}] Counter reset: {username} (IN: {prev_user_in} -> {current_user_in})")
                    
                    if current_user_out >= prev_user_out:
                        user_delta_out = current_user_out - prev_user_out
                    else:
                        user_delta_out = current_user_out
                        logger.info(f"[{server_name}] Counter reset: {username} (OUT: {prev_user_out} -> {current_user_out})")
                else:
                    user_delta_in = current_user_in
                    user_delta_out = current_user_out
                
                total_delta_in += user_delta_in
                total_delta_out += user_delta_out
                
                for session in user_sessions:
                    conn.execute('''
                        INSERT INTO traffic_history (server_name, username, bytes_in, bytes_out, active_users)
                        VALUES (?, ?, ?, ?, 0)
                    ''', (server_name, session.username, session.bytes_received, session.bytes_sent))
            
            conn.execute('''
                INSERT INTO traffic_history (server_name, bytes_in, bytes_out, active_users)
                VALUES (?, ?, ?, ?)
            ''', (server_name, total_delta_in, total_delta_out, active_users))
            
            logger.debug(f"[{server_name}] Traffic snapshot: Δ{total_delta_in/(1024**2):.2f}MB in, Δ{total_delta_out/(1024**2):.2f}MB out, {active_users} unique users")
            
            conn.commit()
    
    def update_user_stats(self, username: str, server_name: str):
        with sqlite3.connect(self.db_path) as conn:
            # Calculate sessions by period
            today = datetime.now().strftime('%Y-%m-%d')
            week_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
            
            # Total stats
            stats = conn.execute('''
                SELECT 
                    COUNT(*) as total_sessions,
                    SUM(CASE 
                        WHEN session_duration IS NOT NULL THEN session_duration
                        ELSE strftime('%s', 'now') - strftime('%s', connected_since)
                    END) as total_time,
                    SUM(bytes_sent) as total_sent,
                    SUM(bytes_received) as total_received,
                    MAX(COALESCE(disconnected_at, connected_since)) as last_seen
                FROM sessions
                WHERE username = ? AND server_name = ?
            ''', (username, server_name)).fetchone()
            
            # Sessions today
            sessions_today = conn.execute('''
                SELECT COUNT(*) FROM sessions
                WHERE username = ? AND server_name = ? 
                AND DATE(connected_since) = ?
            ''', (username, server_name, today)).fetchone()[0]
            
            # Sessions this week
            sessions_week = conn.execute('''
                SELECT COUNT(*) FROM sessions
                WHERE username = ? AND server_name = ? 
                AND connected_since >= ?
            ''', (username, server_name, week_ago)).fetchone()[0]
            
            if stats and stats[0] > 0:
                online = conn.execute('''
                    SELECT COUNT(*) FROM sessions
                    WHERE username = ? AND server_name = ? AND disconnected_at IS NULL
                ''', (username, server_name)).fetchone()[0] > 0
                
                conn.execute('''
                    INSERT OR REPLACE INTO user_stats (
                        username, server_name, total_sessions, total_time_seconds,
                        total_bytes_sent, total_bytes_received,
                        last_seen, current_status, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (
                    username,
                    server_name,
                    stats[0],
                    stats[1] or 0,
                    stats[2] or 0,
                    stats[3] or 0,
                    stats[4],
                    'online' if online else 'offline'
                ))
                
                conn.commit()
                
                # Return session stats for use in aggregated queries
                return {
                    'total': stats[0],
                    'today': sessions_today,
                    'week': sessions_week
                }
    
    def get_active_sessions(self, server_name: Optional[str] = None) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
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
    
    def get_user_stats(self, server_name: Optional[str] = None, limit: int = 50) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            today = datetime.now().strftime('%Y-%m-%d')
            week_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
            
            if server_name:
                # Single server - get stats with session counts by period
                rows = conn.execute('''
                    SELECT 
                        us.*,
                        (SELECT COUNT(*) FROM sessions s 
                         WHERE s.username = us.username AND s.server_name = us.server_name 
                         AND DATE(s.connected_since) = ?) as sessions_today,
                        (SELECT COUNT(*) FROM sessions s 
                         WHERE s.username = us.username AND s.server_name = us.server_name 
                         AND s.connected_since >= ?) as sessions_week
                    FROM user_stats us
                    WHERE us.server_name = ?
                    ORDER BY us.current_status DESC, us.last_seen DESC
                    LIMIT ?
                ''', (today, week_ago, server_name, limit)).fetchall()
            else:
                # All servers - aggregate stats
                rows = conn.execute('''
                    SELECT 
                        us.username,
                        GROUP_CONCAT(DISTINCT us.server_name) as servers,
                        SUM(us.total_sessions) as total_sessions,
                        SUM(us.total_time_seconds) as total_time_seconds,
                        SUM(us.total_bytes_sent) as total_bytes_sent,
                        SUM(us.total_bytes_received) as total_bytes_received,
                        MAX(us.last_seen) as last_seen,
                        MAX(us.current_status) as current_status,
                        (SELECT COUNT(*) FROM sessions s 
                         WHERE s.username = us.username 
                         AND DATE(s.connected_since) = ?) as sessions_today,
                        (SELECT COUNT(*) FROM sessions s 
                         WHERE s.username = us.username 
                         AND s.connected_since >= ?) as sessions_week
                    FROM user_stats us
                    GROUP BY us.username
                    ORDER BY current_status DESC, last_seen DESC
                    LIMIT ?
                ''', (today, week_ago, limit)).fetchall()
            
            return [dict(row) for row in rows]
    
    def get_traffic_history(self, hours: int = 24, server_name: Optional[str] = None) -> Dict:
        """Get traffic history for charts"""
        with sqlite3.connect(self.db_path) as conn:
            since = datetime.now() - timedelta(hours=hours)
            
            if hours <= 0.5:
                interval_format = '%Y-%m-%d %H:%M'
                interval_name = 'minute'
            elif hours <= 6:
                interval_format = '%Y-%m-%d %H:%M'
                interval_name = 'minute'
            elif hours <= 24:
                interval_format = '%Y-%m-%d %H:00'
                interval_name = 'hour'
            else:
                interval_format = '%Y-%m-%d'
                interval_name = 'day'
            
            if server_name:
                query = f'''
                    SELECT 
                        strftime('{interval_format}', timestamp) as time_slot,
                        SUM(bytes_in) as total_in,
                        SUM(bytes_out) as total_out,
                        MAX(active_users) as users
                    FROM traffic_history
                    WHERE timestamp > ? AND server_name = ? AND username IS NULL
                    GROUP BY time_slot
                    ORDER BY time_slot
                '''
                params = (since, server_name)
            else:
                query = f'''
                    SELECT 
                        strftime('{interval_format}', timestamp) as time_slot,
                        server_name,
                        SUM(bytes_in) as total_in,
                        SUM(bytes_out) as total_out,
                        MAX(active_users) as users
                    FROM traffic_history
                    WHERE timestamp > ? AND username IS NULL
                    GROUP BY time_slot, server_name
                    HAVING time_slot IS NOT NULL
                '''
                params = (since,)
                
                rows_raw = conn.execute(query, params).fetchall()
                
                aggregated = {}
                for row in rows_raw:
                    time_slot = row[0]
                    if time_slot not in aggregated:
                        aggregated[time_slot] = {'in': 0, 'out': 0, 'users': 0}
                    aggregated[time_slot]['in'] += (row[2] or 0)
                    aggregated[time_slot]['out'] += (row[3] or 0)
                    aggregated[time_slot]['users'] += (row[4] or 0)
                
                rows = [(k, v['in'], v['out'], v['users']) for k, v in sorted(aggregated.items())]
            
            if server_name:
                rows = conn.execute(query, params).fetchall()
            
            labels = []
            for row in rows:
                time_str = row[0]
                if not time_str:
                    continue
                if interval_name == 'hour':
                    labels.append(time_str.split(' ')[1] if ' ' in time_str else time_str)
                elif interval_name == 'minute':
                    labels.append(time_str.split(' ')[1] if ' ' in time_str else time_str)
                else:
                    labels.append(time_str)
            
            logger.debug(f"Traffic history: {len(rows)} data points, server={server_name}, hours={hours}")
            
            return {
                'labels': labels,
                'inbound': [row[1] / (1024**3) if row[1] else 0 for row in rows],
                'outbound': [row[2] / (1024**3) if row[2] else 0 for row in rows],
                'users': [int(row[3]) if row[3] else 0 for row in rows]
            }
    
    def cleanup_old_data(self):
        """Remove old data based on retention policy"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Calculate cutoff dates
                sessions_cutoff = datetime.now() - timedelta(days=RETENTION_DAYS)
                traffic_cutoff = datetime.now() - timedelta(days=TRAFFIC_HISTORY_RETENTION_DAYS)
                
                # Delete old sessions
                sessions_deleted = conn.execute('''
                    DELETE FROM sessions 
                    WHERE disconnected_at IS NOT NULL 
                    AND disconnected_at < ?
                ''', (sessions_cutoff,)).rowcount
                
                # Delete old traffic history
                traffic_deleted = conn.execute('''
                    DELETE FROM traffic_history 
                    WHERE timestamp < ?
                ''', (traffic_cutoff,)).rowcount
                
                conn.commit()
                
                if sessions_deleted > 0 or traffic_deleted > 0:
                    logger.info(f"Cleanup: Removed {sessions_deleted} old sessions and {traffic_deleted} traffic records")
                    
                return sessions_deleted, traffic_deleted
        except Exception as e:
            logger.error(f"Error during data cleanup: {e}")
            return 0, 0

# OpenVPN Parser for version 2.5.x
class OpenVPNParser:
    def __init__(self, status_file: str, server_name: str = "default"):
        self.status_file = status_file
        self.server_name = server_name
    
    def parse_status_file(self) -> List[VPNSession]:
        sessions = []
        
        if not os.path.exists(self.status_file):
            logger.warning(f"[{self.server_name}] Status file not found: {self.status_file}")
            return sessions
        
        try:
            with open(self.status_file, 'r') as f:
                lines = f.readlines()
            
            logger.debug(f"[{self.server_name}] Parsing status file: {len(lines)} lines")
            
            routing_table = {}
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                
                try:
                    if line.startswith('CLIENT_LIST') and not line.startswith('CLIENT_LIST,Common Name'):
                        parts = line.split(',')
                        
                        if len(parts) >= 8:
                            username = parts[1]
                            real_address_with_port = parts[2]
                            
                            # Extract IP and port separately
                            if ':' in real_address_with_port:
                                real_address, real_address_port = real_address_with_port.rsplit(':', 1)
                            else:
                                real_address = real_address_with_port
                                real_address_port = 'unknown'
                            
                            virtual_address = parts[3] if len(parts) > 3 and parts[3] else None
                            
                            try:
                                bytes_received = int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else 0
                                bytes_sent = int(parts[6]) if len(parts) > 6 and parts[6].isdigit() else 0
                            except (ValueError, IndexError) as e:
                                logger.warning(f"[{self.server_name}] Error parsing bytes on line {line_num}: {e}")
                                bytes_received = 0
                                bytes_sent = 0
                                
                            connected_since_str = parts[7] if len(parts) > 7 else ""
                            
                            try:
                                connected_since = datetime.strptime(connected_since_str, "%Y-%m-%d %H:%M:%S")
                            except (ValueError, IndexError) as e:
                                logger.warning(f"[{self.server_name}] Error parsing date on line {line_num}: {e}")
                                connected_since = datetime.now()
                            
                            session = VPNSession(
                                username=username,
                                real_address=real_address,
                                real_address_port=real_address_port,
                                virtual_address=virtual_address,
                                bytes_received=bytes_received,
                                bytes_sent=bytes_sent,
                                connected_since=connected_since,
                                server_name=self.server_name
                            )
                            
                            sessions.append(session)
                        else:
                            logger.warning(f"[{self.server_name}] Incomplete CLIENT_LIST on line {line_num}")
                    
                    elif line.startswith('ROUTING_TABLE') and ',' in line and not line.startswith('ROUTING_TABLE,Virtual Address'):
                        parts = line.split(',')
                        if len(parts) >= 3:
                            virtual_ip = parts[1]
                            username = parts[2]
                            routing_table[username] = virtual_ip
                            
                except Exception as e:
                    logger.error(f"[{self.server_name}] Error parsing line {line_num}: {e}")
                    continue
            
            # Apply routing table info
            for session in sessions:
                if not session.virtual_address and session.username in routing_table:
                    session.virtual_address = routing_table[session.username]
            
            logger.info(f"[{self.server_name}] Parsed {len(sessions)} sessions")
            
        except IOError as e:
            logger.error(f"[{self.server_name}] I/O error reading status file: {e}")
        except Exception as e:
            logger.error(f"[{self.server_name}] Unexpected error parsing status file: {e}")
        
        return sessions

# Multi-Server Stats Collector
class MultiServerStatsCollector:
    def __init__(self):
        self.db = DatabaseManager(DB_PATH)
        self.parsers = []
        for server in SERVERS:
            self.parsers.append({
                'name': server['name'],
                'parser': OpenVPNParser(server['status_file'], server['name'])
            })
        self.running = False
        self.cleanup_counter = 0  # For periodic cleanup
    
    def collect_stats(self):
        logger.info(f"\n{'='*60}")
        logger.info(f"Collecting statistics at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        for parser_info in self.parsers:
            server_name = parser_info['name']
            parser = parser_info['parser']
            
            logger.info(f"\n[{server_name}] Processing...")
            
            try:
                # Parse current status
                sessions = parser.parse_status_file()
                
                if not sessions:
                    logger.warning(f"[{server_name}] No sessions found")
                    continue
                
                # Save traffic snapshot for charts
                self.db.save_traffic_snapshot(server_name, sessions)
                
                # Get active sessions from DB
                db_active_sessions = self.db.get_active_sessions(server_name)
                
                # Create set of current session keys (username + real_address + port)
                current_session_keys = set()
                for session in sessions:
                    key = (session.username, session.real_address, session.real_address_port)
                    current_session_keys.add(key)
                    self.db.save_session(session)
                    self.db.update_user_stats(session.username, server_name)
                
                # Mark disconnected sessions - check by username + real_address + port
                disconnected_count = 0
                for db_session in db_active_sessions:
                    db_key = (
                        db_session['username'],
                        db_session['real_address'],
                        db_session.get('real_address_port', 'unknown')
                    )
                    
                    if db_key not in current_session_keys:
                        # This specific session is no longer active
                        disconnected_session = VPNSession(
                            username=db_session['username'],
                            real_address=db_session['real_address'],
                            real_address_port=db_session.get('real_address_port', 'unknown'),
                            virtual_address=db_session['virtual_address'],
                            bytes_received=db_session['bytes_received'],
                            bytes_sent=db_session['bytes_sent'],
                            connected_since=datetime.fromisoformat(db_session['connected_since']),
                            server_name=server_name,
                            disconnected_at=datetime.now()
                        )
                        self.db.save_session(disconnected_session)
                        self.db.update_user_stats(db_session['username'], server_name)
                        disconnected_count += 1
                
                logger.info(f"[{server_name}] Updated: {len(sessions)} active, {disconnected_count} disconnected")
                
            except Exception as e:
                logger.error(f"[{server_name}] Error processing server: {e}")
                continue
        
        # Periodic cleanup (every 24 hours = 1440 minutes, assuming 60s interval = 1440 iterations)
        self.cleanup_counter += 1
        if self.cleanup_counter >= 1440:  # Once per day
            logger.info("Running periodic data cleanup...")
            self.db.cleanup_old_data()
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
CORS(app)

db = DatabaseManager(DB_PATH)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/health')
def health():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route('/api/servers')
def api_servers():
    """Get list of configured servers"""
    return jsonify([{"name": s["name"], "status_file": s["status_file"]} for s in SERVERS])

@app.route('/api/active_sessions')
def api_active_sessions():
    server = request.args.get('server')
    sessions = db.get_active_sessions(server)
    
    formatted_sessions = []
    for s in sessions:
        connected_since = datetime.fromisoformat(s['connected_since'])
        duration = int((datetime.now() - connected_since).total_seconds())
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
def api_user_stats():
    server = request.args.get('server')
    limit = min(request.args.get('limit', DEFAULT_LIMIT, type=int), MAX_LIMIT)
    offset = request.args.get('offset', 0, type=int)
    search = request.args.get('search', '').strip()
    
    try:
        stats = db.get_user_stats(server, limit + offset)
        
        # Apply search filter if provided
        if search:
            stats = [s for s in stats if search.lower() in s['username'].lower()]
        
        # Apply pagination
        total_count = len(stats)
        stats = stats[offset:offset + limit]
        
        formatted_stats = []
        for s in stats:
            hours = s['total_time_seconds'] // 3600
            minutes = (s['total_time_seconds'] % 3600) // 60
            time_str = f"{hours}h {minutes}m"
            
            total_bytes = s['total_bytes_sent'] + s['total_bytes_received']
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
                'bytes_sent': s['total_bytes_sent'],
                'bytes_received': s['total_bytes_received'],
                'download_gb': round(s['total_bytes_received'] / (1024**3), 2),
                'upload_gb': round(s['total_bytes_sent'] / (1024**3), 2)
            }
            
            # Add server info if aggregated
            if 'servers' in s:
                formatted_stat['servers'] = s['servers']
            elif 'server_name' in s:
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
def api_traffic_chart():
    """Get traffic chart data"""
    server = request.args.get('server')
    hours = request.args.get('hours', 24, type=float)  # Changed to float to support 0.083 (5 min)
    
    data = db.get_traffic_history(hours, server)
    return jsonify(data)

@app.route('/api/summary')
def api_summary():
    server = request.args.get('server')
    
    with sqlite3.connect(DB_PATH) as conn:
        if server:
            active_users = conn.execute(
                "SELECT COUNT(DISTINCT username) FROM sessions WHERE disconnected_at IS NULL AND server_name = ?",
                (server,)
            ).fetchone()[0]
            
            total_users = conn.execute(
                "SELECT COUNT(DISTINCT username) FROM sessions WHERE server_name = ?",
                (server,)
            ).fetchone()[0]
            
            today = datetime.now().strftime('%Y-%m-%d')
            today_sessions = conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE DATE(connected_since) = ? AND server_name = ?",
                (today, server)
            ).fetchone()[0]
            
            total_traffic = conn.execute(
                "SELECT SUM(bytes_sent + bytes_received) FROM sessions WHERE server_name = ?",
                (server,)
            ).fetchone()[0] or 0
        else:
            active_users = conn.execute(
                "SELECT COUNT(DISTINCT username) FROM sessions WHERE disconnected_at IS NULL"
            ).fetchone()[0]
            
            total_users = conn.execute(
                "SELECT COUNT(DISTINCT username) FROM sessions"
            ).fetchone()[0]
            
            today = datetime.now().strftime('%Y-%m-%d')
            today_sessions = conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE DATE(connected_since) = ?",
                (today,)
            ).fetchone()[0]
            
            total_traffic = conn.execute(
                "SELECT SUM(bytes_sent + bytes_received) FROM sessions"
            ).fetchone()[0] or 0
        
        traffic_gb = round(total_traffic / (1024**3), 2)
        
        # Get server count
        server_count = conn.execute(
            "SELECT COUNT(DISTINCT server_name) FROM sessions"
        ).fetchone()[0]
    
    return jsonify({
        'active_users': active_users,
        'total_users': total_users,
        'today_sessions': today_sessions,
        'total_traffic_gb': traffic_gb,
        'server_count': server_count
    })

@app.route('/api/export/sessions')
def export_sessions():
    """Export active sessions as CSV or JSON"""
    format_type = request.args.get('format', 'csv')
    server = request.args.get('server')
    
    try:
        sessions = db.get_active_sessions(server)
        
        if format_type == 'json':
            return jsonify(sessions)
        
        elif format_type == 'csv':
            output = io.StringIO()
            if sessions:
                fieldnames = sessions[0].keys()
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(sessions)
            
            response = Response(output.getvalue(), mimetype='text/csv')
            response.headers['Content-Disposition'] = f'attachment; filename=vpn_sessions_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            return response
        
        else:
            return jsonify({'error': 'Invalid format. Use csv or json'}), 400
            
    except Exception as e:
        logger.error(f"Error exporting sessions: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/users')
def export_users():
    """Export user statistics as CSV or JSON"""
    format_type = request.args.get('format', 'csv')
    server = request.args.get('server')
    
    try:
        stats = db.get_user_stats(server, MAX_LIMIT)
        
        # Format data for export
        export_data = []
        for s in stats:
            hours = s['total_time_seconds'] // 3600
            minutes = (s['total_time_seconds'] % 3600) // 60
            
            export_row = {
                'username': s['username'],
                'total_sessions': s['total_sessions'],
                'total_time_hours': hours,
                'total_time_minutes': minutes,
                'total_bytes_sent': s['total_bytes_sent'],
                'total_bytes_received': s['total_bytes_received'],
                'total_traffic_gb': round((s['total_bytes_sent'] + s['total_bytes_received']) / (1024**3), 2),
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
            output = io.StringIO()
            if export_data:
                fieldnames = export_data[0].keys()
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(export_data)
            
            response = Response(output.getvalue(), mimetype='text/csv')
            response.headers['Content-Disposition'] = f'attachment; filename=vpn_users_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            return response
        
        else:
            return jsonify({'error': 'Invalid format. Use csv or json'}), 400
            
    except Exception as e:
        logger.error(f"Error exporting user stats: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    logger.info("Starting Multi-Server OpenVPN Statistics System")
    logger.info(f"Database: {DB_PATH}")
    logger.info(f"Update interval: {UPDATE_INTERVAL} seconds")
    logger.info(f"Data retention: {RETENTION_DAYS} days (sessions), {TRAFFIC_HISTORY_RETENTION_DAYS} days (traffic)")
    logger.info(f"Configured servers:")
    for server in SERVERS:
        logger.info(f"  - {server['name']}: {server['status_file']}")
    logger.info("="*60)
    
    # Start stats collector in background thread
    collector = MultiServerStatsCollector()
    collector_thread = threading.Thread(target=collector.run, daemon=True)
    collector_thread.start()
    
    # Run Flask
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False)
