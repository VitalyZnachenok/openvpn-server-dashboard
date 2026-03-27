#!/usr/bin/env python3
"""
One-time migration script for upgrading to the optimized version.
Run BEFORE starting the updated container, or exec into the container:
    docker exec -it openvpn-stats python migrate.py

What it does:
  1. Purges old per-session traffic snapshots (only latest needed for deltas)
  2. Recalculates user_stats from actual session data
  3. Removes orphaned user_stats entries
  4. Runs VACUUM to reclaim disk space
"""

import os
import sys
import sqlite3
from datetime import datetime

DB_PATH = os.getenv("DB_PATH", "/app/data/openvpn_stats.db")

if not os.path.exists(DB_PATH):
    # Try local path for running outside container
    local_path = os.path.join(os.path.dirname(__file__), "data", "openvpn_stats.db")
    if os.path.exists(local_path):
        DB_PATH = local_path
    else:
        print(f"Database not found at {DB_PATH}")
        sys.exit(1)

def get_db_size(path):
    return os.path.getsize(path) / (1024 * 1024)

def migrate():
    print(f"Database: {DB_PATH}")
    print(f"Size before: {get_db_size(DB_PATH):.1f} MB")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")

    # --- Step 1: Count current state ---
    total_traffic_rows = conn.execute("SELECT COUNT(*) FROM traffic_history").fetchone()[0]
    session_snapshot_rows = conn.execute(
        "SELECT COUNT(*) FROM traffic_history WHERE session_key IS NOT NULL"
    ).fetchone()[0]
    aggregate_rows = total_traffic_rows - session_snapshot_rows
    print(f"\ntraffic_history: {total_traffic_rows} total rows")
    print(f"  - per-session snapshots: {session_snapshot_rows}")
    print(f"  - aggregate (chart data): {aggregate_rows}")

    total_sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    active_sessions = conn.execute(
        "SELECT COUNT(*) FROM sessions WHERE disconnected_at IS NULL"
    ).fetchone()[0]
    user_stats_rows = conn.execute("SELECT COUNT(*) FROM user_stats").fetchone()[0]
    print(f"\nsessions: {total_sessions} total ({active_sessions} active)")
    print(f"user_stats: {user_stats_rows} rows")

    # --- Step 2: Purge old per-session snapshots ---
    # Keep only the latest batch per server (needed for next delta calculation)
    print("\n--- Purging old per-session snapshots ---")

    # For each server, find the latest timestamp and keep only those rows
    servers = conn.execute(
        "SELECT DISTINCT server_name FROM traffic_history WHERE session_key IS NOT NULL"
    ).fetchall()

    kept = 0
    for (server_name,) in servers:
        latest_ts = conn.execute('''
            SELECT MAX(timestamp) FROM traffic_history
            WHERE server_name = ? AND session_key IS NOT NULL
        ''', (server_name,)).fetchone()[0]

        if latest_ts:
            latest_count = conn.execute('''
                SELECT COUNT(*) FROM traffic_history
                WHERE server_name = ? AND session_key IS NOT NULL AND timestamp = ?
            ''', (server_name, latest_ts)).fetchone()[0]
            kept += latest_count
            print(f"  [{server_name}] keeping {latest_count} rows from {latest_ts}")

    deleted = conn.execute('''
        DELETE FROM traffic_history
        WHERE session_key IS NOT NULL
        AND id NOT IN (
            SELECT th.id FROM traffic_history th
            INNER JOIN (
                SELECT server_name, MAX(timestamp) as max_ts
                FROM traffic_history
                WHERE session_key IS NOT NULL
                GROUP BY server_name
            ) latest ON th.server_name = latest.server_name 
                    AND th.timestamp = latest.max_ts
            WHERE th.session_key IS NOT NULL
        )
    ''').rowcount
    conn.commit()
    print(f"  Deleted: {deleted} rows, kept: {kept}")

    # --- Step 3: Remove orphaned user_stats ---
    print("\n--- Cleaning orphaned user_stats ---")
    orphaned = conn.execute('''
        DELETE FROM user_stats
        WHERE (username, server_name) NOT IN (
            SELECT DISTINCT username, server_name FROM sessions
        )
    ''').rowcount
    conn.commit()
    print(f"  Removed: {orphaned} orphaned entries")

    # --- Step 4: Recalculate user_stats from sessions ---
    print("\n--- Recalculating user_stats ---")
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
                    ELSE strftime('%s', 'now') - strftime('%s', s.connected_since)
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
            current_status = (
                SELECT CASE WHEN COUNT(*) > 0 THEN 'online' ELSE 'offline' END
                FROM sessions s
                WHERE s.username = user_stats.username
                AND s.server_name = user_stats.server_name
                AND s.disconnected_at IS NULL
            ),
            updated_at = CURRENT_TIMESTAMP
    ''')
    updated = conn.execute("SELECT changes()").fetchone()[0]
    conn.commit()
    print(f"  Recalculated: {updated} entries")

    # --- Step 5: VACUUM ---
    print("\n--- Running VACUUM ---")
    conn.execute("VACUUM")
    conn.close()

    print(f"\nSize after: {get_db_size(DB_PATH):.1f} MB")
    print(f"Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)
    print("Migration complete. You can now start the updated container.")


if __name__ == "__main__":
    migrate()
