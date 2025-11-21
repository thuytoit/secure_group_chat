import sqlite3
import json
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple

DB_PATH = Path(__file__).parent / 'chat.db'

# Thread-local storage for database connections
_local = threading.local()

def get_db():
    """Get thread-local database connection with proper configuration"""
    if not hasattr(_local, 'conn') or _local.conn is None:
        _local.conn = sqlite3.connect(
            DB_PATH, 
            timeout=30.0,
            check_same_thread=False,
            isolation_level=None
        )
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute('PRAGMA journal_mode=WAL')
        _local.conn.execute('PRAGMA busy_timeout=30000')
    return _local.conn

def close_db():
    """Close thread-local database connection"""
    if hasattr(_local, 'conn') and _local.conn is not None:
        _local.conn.close()
        _local.conn = None

def init_db():
    """Initialize database schema"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rooms (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            type TEXT NOT NULL DEFAULT 'public',
            creator TEXT NOT NULL,
            password_hash TEXT,
            invite_code TEXT,
            created_at REAL NOT NULL,
            key_version INTEGER DEFAULT 0,
            description TEXT,
            max_members INTEGER DEFAULT 50
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS room_members (
            room_id TEXT NOT NULL,
            username TEXT NOT NULL,
            role TEXT DEFAULT 'member',
            joined_at REAL NOT NULL,
            first_join_at REAL NOT NULL,
            PRIMARY KEY (room_id, username),
            FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id TEXT NOT NULL,
            sender TEXT NOT NULL,
            encrypted_content TEXT NOT NULL,
            timestamp REAL NOT NULL,
            deleted INTEGER DEFAULT 0,
            deleted_by TEXT,
            deleted_at REAL,
            key_version INTEGER DEFAULT 0,
            file_metadata TEXT,
            FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            emoji TEXT NOT NULL,
            timestamp REAL NOT NULL,
            UNIQUE(message_id, username, emoji),
            FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id TEXT NOT NULL,
            reporter TEXT NOT NULL,
            reason TEXT NOT NULL,
            details TEXT,
            timestamp REAL NOT NULL,
            status TEXT DEFAULT 'pending',
            resolved_by TEXT,
            resolved_at REAL,
            FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE
        )
    ''')
    
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id, timestamp DESC)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_room_members ON room_members(username)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status)')
    
    conn.commit()

# ===== ROOM OPERATIONS =====

def create_room(room_id: str, name: str, creator: str, room_type: str = 'public', 
                password_hash: Optional[str] = None, invite_code: Optional[str] = None,
                description: str = '', max_members: int = 50) -> bool:
    """Create a new room"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO rooms (id, name, type, creator, password_hash, invite_code, 
                             created_at, description, max_members)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (room_id, name, room_type, creator, password_hash, invite_code, 
              datetime.now().timestamp(), description, max_members))
        
        # Add creator as admin
        now = datetime.now().timestamp()
        cursor.execute('''
            INSERT INTO room_members (room_id, username, role, joined_at, first_join_at)
            VALUES (?, ?, 'admin', ?, ?)
        ''', (room_id, creator, now, now))
        
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def get_room(room_id: str) -> Optional[Dict]:
    """Get room details"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM rooms WHERE id = ?', (room_id,))
    row = cursor.fetchone()
    return dict(row) if row else None

def list_public_rooms() -> List[Dict]:
    """List all public rooms with member counts"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT r.*, COUNT(rm.username) as member_count
        FROM rooms r
        LEFT JOIN room_members rm ON r.id = rm.room_id
        WHERE r.type = 'public'
        GROUP BY r.id
        ORDER BY r.created_at DESC
    ''')
    rows = cursor.fetchall()
    return [dict(row) for row in rows]

def get_user_rooms(username: str) -> List[Dict]:
    """Get all rooms a user is a member of"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT r.*, rm.role, rm.joined_at, COUNT(rm2.username) as member_count
        FROM rooms r
        JOIN room_members rm ON r.id = rm.room_id
        LEFT JOIN room_members rm2 ON r.id = rm2.room_id
        WHERE rm.username = ?
        GROUP BY r.id
        ORDER BY rm.joined_at DESC
    ''', (username,))
    rows = cursor.fetchall()
    return [dict(row) for row in rows]

def delete_room(room_id: str) -> bool:
    """Delete a room and all associated data"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM rooms WHERE id = ?', (room_id,))
        conn.commit()
        return True
    except:
        return False

def update_room_key_version(room_id: str, version: int):
    """Update room's key version after rotation"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE rooms SET key_version = ? WHERE id = ?', (version, room_id))
    conn.commit()

# ===== MEMBER OPERATIONS =====

def add_member(room_id: str, username: str, role: str = 'member') -> bool:
    """Add user to room, preserving role and first_join_at if already member"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        now = datetime.now().timestamp()
        
        # Check if user was previously a member
        cursor.execute('''
            SELECT role, first_join_at FROM room_members 
            WHERE room_id = ? AND username = ?
        ''', (room_id, username))
        existing = cursor.fetchone()
        
        if existing:
            # Rejoining - preserve role and first_join_at
            cursor.execute('''
                INSERT OR REPLACE INTO room_members 
                (room_id, username, role, joined_at, first_join_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (room_id, username, existing['role'], now, existing['first_join_at']))
        else:
            # New join - use provided role and set both timestamps to now
            cursor.execute('''
                INSERT INTO room_members (room_id, username, role, joined_at, first_join_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (room_id, username, role, now, now))
        
        conn.commit()
        return True
    except Exception as e:
        print(f"Error adding member: {e}")
        return False

def remove_member(room_id: str, username: str, wipe_history: bool = False) -> bool:
    """Remove user from room"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Always delete from room_members
        cursor.execute('''
            DELETE FROM room_members WHERE room_id = ? AND username = ?
        ''', (room_id, username))
        
        conn.commit()
        return True
    except:
        return False

def get_member_role(room_id: str, username: str) -> Optional[str]:
    """Get user's role in a room"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT role FROM room_members WHERE room_id = ? AND username = ?
    ''', (room_id, username))
    row = cursor.fetchone()
    return row['role'] if row else None

def get_room_members(room_id: str) -> List[Dict]:
    """Get all members of a room"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT username, role, joined_at, first_join_at 
        FROM room_members WHERE room_id = ?
        ORDER BY joined_at ASC
    ''', (room_id,))
    rows = cursor.fetchall()
    return [dict(row) for row in rows]

def transfer_admin(room_id: str, new_admin: str) -> bool:
    """Transfer admin role to another user"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE room_members SET role = 'admin' WHERE room_id = ? AND username = ?
        ''', (room_id, new_admin))
        conn.commit()
        return True
    except:
        return False

def get_next_admin(room_id: str, exclude: str) -> Optional[str]:
    """Get next member to become admin (oldest join)"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT username FROM room_members 
        WHERE room_id = ? AND username != ?
        ORDER BY joined_at ASC LIMIT 1
    ''', (room_id, exclude))
    row = cursor.fetchone()
    return row['username'] if row else None

# ===== MESSAGE OPERATIONS =====

def save_message(room_id: str, sender: str, encrypted_content: str, 
                key_version: int = 0, file_metadata: Optional[Dict] = None) -> int:
    """Save encrypted message to database"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO messages (room_id, sender, encrypted_content, timestamp, key_version, file_metadata)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (room_id, sender, encrypted_content, datetime.now().timestamp(), key_version,
          json.dumps(file_metadata) if file_metadata else None))
    msg_id = cursor.lastrowid
    conn.commit()
    return msg_id

def get_messages(room_id: str, user_first_join: float, limit: int = 50, 
                before_id: Optional[int] = None) -> List[Dict]:
    """Get messages for a room (only from user's first join onwards)"""
    conn = get_db()
    cursor = conn.cursor()
    
    query = '''
        SELECT m.*, GROUP_CONCAT(r.emoji || ':' || r.username, '|') as reactions
        FROM messages m
        LEFT JOIN reactions r ON m.id = r.message_id
        WHERE m.room_id = ? AND m.timestamp >= ? AND m.deleted = 0
    '''
    params = [room_id, user_first_join]
    
    if before_id:
        query += ' AND m.id < ?'
        params.append(before_id)
    
    query += ' GROUP BY m.id ORDER BY m.id DESC LIMIT ?'
    params.append(limit)
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    messages = []
    for row in rows:
        msg = dict(row)
        # Parse reactions
        if msg['reactions']:
            reactions_dict = {}
            for reaction in msg['reactions'].split('|'):
                emoji, user = reaction.split(':')
                if emoji not in reactions_dict:
                    reactions_dict[emoji] = []
                reactions_dict[emoji].append(user)
            msg['reactions'] = reactions_dict
        else:
            msg['reactions'] = {}
        
        # Parse file metadata
        if msg['file_metadata']:
            msg['file_metadata'] = json.loads(msg['file_metadata'])
        
        messages.append(msg)
    
    return list(reversed(messages))

def delete_message(message_id: int, deleted_by: str) -> bool:
    """Soft delete a message"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE messages SET deleted = 1, deleted_by = ?, deleted_at = ?
            WHERE id = ?
        ''', (deleted_by, datetime.now().timestamp(), message_id))
        conn.commit()
        return True
    except:
        return False

def get_message_sender(message_id: int) -> Optional[str]:
    """Get the sender of a message"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT sender, room_id FROM messages WHERE id = ?', (message_id,))
    row = cursor.fetchone()
    return dict(row) if row else None

# ===== REACTION OPERATIONS =====

def add_reaction(message_id: int, username: str, emoji: str) -> bool:
    """Add reaction to a message"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR IGNORE INTO reactions (message_id, username, emoji, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (message_id, username, emoji, datetime.now().timestamp()))
        conn.commit()
        return True
    except:
        return False

def remove_reaction(message_id: int, username: str, emoji: str) -> bool:
    """Remove reaction from a message"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            DELETE FROM reactions WHERE message_id = ? AND username = ? AND emoji = ?
        ''', (message_id, username, emoji))
        conn.commit()
        return True
    except:
        return False

def get_message_reactions(message_id: int) -> Dict:
    """Get all reactions for a message"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT emoji, username FROM reactions WHERE message_id = ?
    ''', (message_id,))
    rows = cursor.fetchall()
    
    reactions = {}
    for row in rows:
        emoji = row['emoji']
        username = row['username']
        if emoji not in reactions:
            reactions[emoji] = []
        reactions[emoji].append(username)
    return reactions

# ===== REPORT OPERATIONS =====

def create_report(room_id: str, reporter: str, reason: str, details: str = '') -> int:
    """Create a new report"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO reports (room_id, reporter, reason, details, timestamp)
        VALUES (?, ?, ?, ?, ?)
    ''', (room_id, reporter, reason, details, datetime.now().timestamp()))
    report_id = cursor.lastrowid
    conn.commit()
    return report_id

def get_pending_reports() -> List[Dict]:
    """Get all pending reports for global admin"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT rep.*, r.name as room_name
        FROM reports rep
        JOIN rooms r ON rep.room_id = r.id
        WHERE rep.status = 'pending'
        ORDER BY rep.timestamp DESC
    ''')
    rows = cursor.fetchall()
    return [dict(row) for row in rows]

def resolve_report(report_id: int, resolved_by: str, status: str = 'resolved') -> bool:
    """Resolve a report"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE reports SET status = ?, resolved_by = ?, resolved_at = ?
            WHERE id = ?
        ''', (status, resolved_by, datetime.now().timestamp(), report_id))
        conn.commit()
        return True
    except:
        return False

def update_room_details(room_id: str, name: str, description: str, max_members: int) -> bool:
    """Update room name, description and max members"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE rooms SET name = ?, description = ?, max_members = ? WHERE id = ?
        ''', (name, description, max_members, room_id))
        conn.commit()
        return True
    except:
        return False

def update_room_password(room_id: str, password_hash: Optional[str]) -> bool:
    """Update room password (can be None to remove password)"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE rooms SET password_hash = ? WHERE id = ?
        ''', (password_hash, room_id))
        conn.commit()
        return True
    except:
        return False

def find_room_by_invite_code(invite_code: str) -> Optional[Dict]:
    """Find a room by invite code"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT r.*, COUNT(rm.username) as member_count
        FROM rooms r
        LEFT JOIN room_members rm ON r.id = rm.room_id
        WHERE r.invite_code = ?
        GROUP BY r.id
    ''', (invite_code,))
    row = cursor.fetchone()
    
    if row:
        result = dict(row)
        # Don't expose password_hash, just indicate if it exists
        result['has_password'] = bool(result.get('password_hash'))
        result.pop('password_hash', None)
        return result
    return None

def search_rooms_by_name(query: str) -> List[Dict]:
    """Search public rooms by name"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT r.*, COUNT(rm.username) as member_count
        FROM rooms r
        LEFT JOIN room_members rm ON r.id = rm.room_id
        WHERE r.type = 'public' AND LOWER(r.name) LIKE ?
        GROUP BY r.id
        ORDER BY r.created_at DESC
    ''', (f'%{query}%',))
    rows = cursor.fetchall()
    return [dict(row) for row in rows]

# Initialize database on import
init_db()