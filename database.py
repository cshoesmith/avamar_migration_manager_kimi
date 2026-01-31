import sqlite3
import os
from datetime import datetime
from werkzeug.security import generate_password_hash

DB_NAME = "migration_status.db"


def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    c = conn.cursor()

    # Table to track Users
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    ''')
    
    # Check if admin exists, if not create default users
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        # Use environment variable for default password or generate random
        import secrets
        default_password = os.environ.get('DEFAULT_ADMIN_PASSWORD')
        if not default_password:
            default_password = secrets.token_urlsafe(12)
            print(f"WARNING: Generated random admin password: {default_password}")
            print("WARNING: Please change this password immediately after first login!")
        
        admin_hash = generate_password_hash(default_password)
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", 
                 ('admin', admin_hash, 'admin'))
        print("Initialized default admin user")

    # Table to track the Replication Groups we create
    c.execute('''
        CREATE TABLE IF NOT EXISTS replication_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_name TEXT UNIQUE NOT NULL,
            source_system TEXT NOT NULL,
            destination_system TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'ACTIVE'
        )
    ''')

    # Table to track individual clients within those jobs
    c.execute('''
        CREATE TABLE IF NOT EXISTS migrated_clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id INTEGER,
            client_name TEXT NOT NULL,
            client_domain TEXT NOT NULL,
            client_cid TEXT,
            status TEXT DEFAULT 'PENDING',
            source_backup_count INTEGER DEFAULT 0,
            dest_backup_count INTEGER DEFAULT 0,
            source_total_bytes INTEGER DEFAULT 0,
            dest_total_bytes INTEGER DEFAULT 0,
            dest_client_domain TEXT,
            in_policy_groups INTEGER DEFAULT 1,
            last_checked_at TIMESTAMP,
            notes TEXT,
            FOREIGN KEY (job_id) REFERENCES replication_jobs (id)
        )
    ''')

    # Audit Logs
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user TEXT NOT NULL,
            event_type TEXT NOT NULL,
            description TEXT,
            incident_ref TEXT,
            archived INTEGER DEFAULT 0
        )
    ''')
    
    # Migration: Add archived column if it doesn't exist (for existing databases)
    try:
        c.execute("SELECT archived FROM audit_logs LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE audit_logs ADD COLUMN archived INTEGER DEFAULT 0")
        print("Migration: Added 'archived' column to audit_logs table")
    
    conn.commit()
    conn.close()


def log_migration_job(group_name, source, destination, client_list):
    """
    client_list should be a list of dicts: {'name': 'server1', 'domain': '/clients', 'id': '...'}
    """
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute(
            "INSERT INTO replication_jobs (group_name, source_system, destination_system) VALUES (?, ?, ?)",
            (group_name, source, destination)
        )
        job_id = cur.lastrowid
        
        for client in client_list:
            c_name = client.get('name', 'Unknown')
            c_domain = client.get('domain', 'Unknown')
            c_id = client.get('id', '')
            
            cur.execute(
                "INSERT INTO migrated_clients (job_id, client_name, client_domain, client_cid) VALUES (?, ?, ?, ?)",
                (job_id, c_name, c_domain, c_id)
            )
        
        conn.commit()
        return job_id
    except Exception as e:
        conn.rollback()
        print(f"Error logging migration: {e}")
        return None
    finally:
        conn.close()


def get_all_migrations():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        SELECT j.id, j.group_name, j.source_system, j.destination_system, j.created_at, j.status,
               COUNT(c.id) as client_count,
               SUM(CASE WHEN c.status = 'SYNCED' THEN 1 ELSE 0 END) as synced_count
        FROM replication_jobs j
        LEFT JOIN migrated_clients c ON j.id = c.job_id
        GROUP BY j.id
        ORDER BY j.created_at DESC
    ''')
    jobs = [dict(row) for row in cur.fetchall()]
    conn.close()
    return jobs


def get_clients_for_job(job_identifier):
    """
    Get clients for a job by either job ID (int) or group name (string).
    """
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Check if identifier is likely an ID (int) or Name (str)
    is_id = False
    if isinstance(job_identifier, int):
        is_id = True
    elif isinstance(job_identifier, str) and job_identifier.isdigit():
        is_id = True
        
    if is_id:
        cur.execute('SELECT * FROM migrated_clients WHERE job_id = ?', (job_identifier,))
    else:
        # Assume it's a group_name
        cur.execute('SELECT id FROM replication_jobs WHERE group_name = ?', (job_identifier,))
        row = cur.fetchone()
        if row:
            job_id = row['id']
            cur.execute('SELECT * FROM migrated_clients WHERE job_id = ?', (job_id,))
        else:
            conn.close()
            return []

    clients = [dict(row) for row in cur.fetchall()]
    conn.close()
    return clients


def update_client_status(client_id, source_count=None, dest_count=None, status=None, notes=None, 
                         dest_domain=None, source_bytes=None, dest_bytes=None, **kwargs):
    """
    Update the status of a specific client in the migrated_clients table.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    
    fields = []
    values = []
    
    if source_count is not None:
        fields.append("source_backup_count = ?")
        values.append(source_count)
    if dest_count is not None:
        fields.append("dest_backup_count = ?")
        values.append(dest_count)
    if source_bytes is not None:
        fields.append("source_total_bytes = ?")
        values.append(source_bytes)
    if dest_bytes is not None:
        fields.append("dest_total_bytes = ?")
        values.append(dest_bytes)
    if status is not None:
        fields.append("status = ?")
        values.append(status)
    if notes is not None:
        fields.append("notes = ?")
        values.append(notes)
    if dest_domain is not None:
        fields.append("dest_client_domain = ?")
        values.append(dest_domain)
    if kwargs.get('in_policy_groups') is not None:
        fields.append("in_policy_groups = ?")
        values.append(int(kwargs.get('in_policy_groups')))

    if fields:
        fields.append("last_checked_at = CURRENT_TIMESTAMP")
        query = f"UPDATE migrated_clients SET {', '.join(fields)} WHERE id = ?"
        values.append(client_id)
        cur.execute(query, tuple(values))
        conn.commit()
        
    conn.close()


def get_job_details(job_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM replication_jobs WHERE id = ?", (job_id,))
    job = cur.fetchone()
    conn.close()
    if job:
        return dict(job)
    return None


def get_user_by_username(username):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    conn.close()
    if user:
        return dict(user)
    return None


def get_user_by_id(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    conn.close()
    if user:
        return dict(user)
    return None


def log_audit_event(user, event_type, description, incident_ref=None):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO audit_logs (user, event_type, description, incident_ref) VALUES (?, ?, ?, ?)",
            (user, event_type, description, incident_ref)
        )
        conn.commit()
    except Exception as e:
        print(f"Error logging audit event: {e}")
    finally:
        conn.close()


def get_audit_logs(limit=100, include_archived=False):
    conn = get_db_connection()
    cur = conn.cursor()
    if include_archived:
        cur.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    else:
        cur.execute("SELECT * FROM audit_logs WHERE archived = 0 ORDER BY timestamp DESC LIMIT ?", (limit,))
    logs = [dict(row) for row in cur.fetchall()]
    conn.close()
    return logs


def archive_audit_logs():
    """Mark all non-archived audit logs as archived (soft delete)."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE audit_logs SET archived = 1 WHERE archived = 0")
        archived_count = cur.rowcount
        conn.commit()
        return archived_count
    except Exception as e:
        print(f"Error archiving audit logs: {e}")
        return 0
    finally:
        conn.close()


def delete_migration_job(job_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM migrated_clients WHERE job_id = ?", (job_id,))
        cur.execute("DELETE FROM replication_jobs WHERE id = ?", (job_id,))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error deleting job {job_id}: {e}")
        return False
    finally:
        conn.close()


def reset_configuration():
    """Wipes all migration data and logs, but keeps users"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("DELETE FROM migrated_clients")
        cur.execute("DELETE FROM replication_jobs")
        cur.execute("DELETE FROM audit_logs")
        
        cur.execute("DELETE FROM sqlite_sequence WHERE name='migrated_clients'")
        cur.execute("DELETE FROM sqlite_sequence WHERE name='replication_jobs'")
        cur.execute("DELETE FROM sqlite_sequence WHERE name='audit_logs'")
        
        conn.commit()
        return True
    except Exception as e:
        print(f"Error resetting DB: {e}")
        return False
    finally:
        conn.close()
