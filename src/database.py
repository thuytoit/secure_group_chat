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
    """
    Get thread-local database connection with proper SQLite configuration.
    
    Creates a new SQLite connection for each thread using thread-local storage.
    Configures the connection with Write-Ahead Logging (WAL) mode for better
    concurrency and sets a 30-second timeout for busy database operations.
    
    Returns:
        sqlite3.Connection: Thread-safe database connection
    
    Note:
        Each thread gets its own connection to prevent race conditions.
        Row factory is set to sqlite3.Row for dict-like access to results.
    """
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
    """
    Close thread-local database connection safely.
    
    Closes and cleans up the database connection associated with the
    current thread. Called during application shutdown or thread cleanup.
    """
    if hasattr(_local, 'conn') and _local.conn is not None:
        _local.conn.close()
        _local.conn = None

def init_db():
    """
    Initialize database schema with all required tables and indexes.
    
    Creates the complete database structure including:
    - rooms: Chat room information and settings
    - room_members: User membership and roles in rooms
    - messages: Encrypted message history
    - reactions: Message reactions (emojis)
    - reports: Moderation reports for rooms
    
    Also creates indexes for optimizing common queries (room lookups,
    message retrieval, report filtering).
    
    Note:
        Safe to call multiple times - uses CREATE TABLE IF NOT EXISTS.
        Called automatically when the module is imported.
    """
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
    """
    Create a new chat room in the database.
    
    Inserts a new room record and automatically adds the creator as an admin
    member. Room names must be unique across the system.
    
    Args:
        room_id (str): Unique room identifier (generated by application)
        name (str): Display name for the room (must be unique)
        creator (str): Username of the room creator
        room_type (str): 'public' or 'private'. Defaults to 'public'
        password_hash (str, optional): Bcrypt hash of room password (private rooms only)
        invite_code (str, optional): Unique invite code (private rooms only)
        description (str): Optional room description. Defaults to empty string
        max_members (int): Maximum number of members allowed. Defaults to 50
    
    Returns:
        bool: True if room created successfully, False if name already exists
    
    Note:
        Creator is automatically assigned 'admin' role with both joined_at
        and first_join_at set to current timestamp.
    """
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
    """
    Retrieve complete room information by room ID.
    
    Args:
        room_id (str): Unique room identifier
    
    Returns:
        dict or None: Room data including id, name, type, creator, password_hash,
                      invite_code, created_at, key_version, description, max_members
                      Returns None if room doesn't exist
    
    Example:
        >>> room = get_room("room_abc123")
        >>> print(room['name'])
        'General Chat'
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM rooms WHERE id = ?', (room_id,))
    row = cursor.fetchone()
    return dict(row) if row else None

def list_public_rooms() -> List[Dict]:
    """
    Get all public rooms with their current member counts.
    
    Retrieves all rooms with type='public' and counts active members for each.
    Results are ordered by creation date (newest first).
    
    Returns:
        list: List of room dicts with added 'member_count' field
              Each dict contains all room fields plus member_count
    
    Note:
        Used for displaying available public rooms in the hub interface.
    """
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

def list_all_rooms() -> List[Dict]:
    """
    Get all rooms from database (both public and private).
    
    Used during server startup to populate room_keys dict with version info.
    
    Returns:
        list: All rooms with fields: id, name, type, key_version, etc.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, name, type, key_version, invite_code, password_hash, creator
        FROM rooms
        ORDER BY created_at DESC
    ''')
    rows = cursor.fetchall()
    return [dict(row) for row in rows]

def get_user_rooms(username: str) -> List[Dict]:
    """
    Get all rooms a specific user is a member of.
    
    Retrieves rooms the user belongs to, including their role in each room
    and the current member count. Results ordered by join date (most recent first).
    
    Args:
        username (str): Username to lookup rooms for
    
    Returns:
        list: Rooms with added fields: role, joined_at, member_count
              Empty list if user is not in any rooms
    
    Example:
        >>> rooms = get_user_rooms("alice")
        >>> for room in rooms:
        ...     print(f"{room['name']} - {room['role']}")
    """
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
    """
    Permanently delete a room and all associated data.
    
    Cascade deletes all related records due to foreign key constraints:
    - All messages in the room
    - All member records
    - All reactions on messages
    - All reports for the room
    
    Args:
        room_id (str): Room to delete
    
    Returns:
        bool: True if deletion successful, False otherwise
    
    Warning:
        This operation is IRREVERSIBLE. All data is permanently lost.
    """
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM rooms WHERE id = ?', (room_id,))
        conn.commit()
        return True
    except:
        return False

def update_room_key_version(room_id: str, version: int):
    """
    Update the encryption key version number for a room.
    
    Called after key rotation events (e.g., when a user is kicked).
    Stores the new version number so clients know which key to use
    for decryption and the server can regenerate the correct key.
    
    Args:
        room_id (str): Room to update
        version (int): New key version number (typically previous + 1)
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE rooms SET key_version = ? WHERE id = ?', (version, room_id))
    conn.commit()

# ===== MEMBER OPERATIONS =====

def add_member(room_id: str, username: str, role: str = 'member') -> bool:
    """
    Add a user to a room with intelligent timestamp handling.
    
    Handles both new joins and reconnections:
    - New join: Sets both joined_at and first_join_at to current time
    - Reconnection: Preserves original timestamps to maintain message history access
    
    Args:
        room_id (str): Room to add user to
        username (str): Username to add
        role (str): User role ('admin' or 'member'). Defaults to 'member'
    
    Returns:
        bool: True if successful, False on error
    
    Note:
        CRITICAL for message history: Reconnecting users keep their original
        first_join_at timestamp so they can still see old messages they had
        access to before disconnecting.
    """
    try:
        conn = get_db()
        cursor = conn.cursor()
        now = datetime.now().timestamp()
        
        # Check if user is currently a member
        cursor.execute('''
            SELECT role, joined_at, first_join_at FROM room_members 
            WHERE room_id = ? AND username = ?
        ''', (room_id, username))
        existing = cursor.fetchone()
        
        if existing:
            # User is ALREADY a member - this is a RECONNECTION (page refresh, etc.)
            # CRITICAL: Keep existing joined_at and first_join_at so they see full history
            cursor.execute('''
                INSERT OR REPLACE INTO room_members 
                (room_id, username, role, joined_at, first_join_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (room_id, username, existing['role'], existing['joined_at'], existing['first_join_at']))
            print(f"[DB] Reconnection: {username} preserved joined_at={existing['joined_at']}, first_join_at={existing['first_join_at']}")
        else:
            # New join (first time or after being kicked) - set both timestamps to now
            cursor.execute('''
                INSERT INTO room_members (room_id, username, role, joined_at, first_join_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (room_id, username, role, now, now))
            print(f"[DB] New join: {username} joined_at={now}")
        
        conn.commit()
        return True
    except Exception as e:
        print(f"[DB] Error adding member: {e}")
        return False
                
def remove_member(room_id: str, username: str) -> bool:
    """
    Remove a user from a room's member list.
    
    Deletes the user's membership record, preventing future access to the room.
    future functionality to delete the user's message history.
    
    Args:
        room_id (str): Room to remove user from
        username (str): Username to remove
    
    Returns:
        bool: True if removal successful, False otherwise
    
    Note:
        User will need to rejoin (with proper authorization) to regain access.
        Their old first_join_at timestamp is lost, so they won't see old messages.
    """
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
    """
    Get a user's role in a specific room.
    
    Checks if a user is a member of a room and returns their role
    (either 'admin' or 'member').
    
    Args:
        room_id (str): Room to check
        username (str): User to look up
    
    Returns:
        str or None: 'admin', 'member', or None if not in room
    
    Note:
        Used for authorization checks throughout the application.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT role FROM room_members WHERE room_id = ? AND username = ?
    ''', (room_id, username))
    row = cursor.fetchone()
    return row['role'] if row else None

def get_room_members(room_id: str) -> List[Dict]:
    """
    Get list of all current members in a room with online status.
    
    Retrieves member information including roles, timestamps, and online status,
    ordered by join date (oldest members first).
    
    Args:
        room_id (str): Room to get members for
    
    Returns:
        list: Member records with fields: username, role, joined_at, first_join_at,
              is_online, last_seen
              Empty list if room has no members
    
    Note:
        first_join_at is critical for determining which messages each user
        should be able to decrypt based on their history in the room.
        is_online shows real-time connection status.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT username, role, joined_at, first_join_at, is_online, last_seen
        FROM room_members WHERE room_id = ?
        ORDER BY joined_at ASC
    ''', (room_id,))
    rows = cursor.fetchall()
    
    members = []
    for row in rows:
        member_dict = dict(row)
        # Ensure is_online exists (for backwards compatibility)
        if 'is_online' not in member_dict or member_dict['is_online'] is None:
            member_dict['is_online'] = 0
        if 'last_seen' not in member_dict or member_dict['last_seen'] is None:
            member_dict['last_seen'] = 0
        members.append(member_dict)
    
    return members

def set_user_online_status(username: str, room_id: str, is_online: bool) -> bool:
    """
    Update user's online status in a room.
    
    Called when user connects or disconnects from a room. Updates the
    is_online flag and last_seen timestamp for presence tracking.
    
    Args:
        username (str): User to update
        room_id (str): Room to update status in
        is_online (bool): True if user is online, False if offline
    
    Returns:
        bool: True if update successful, False otherwise
    
    Note:
        This enables real-time "who's online" indicators in the member list.
    """
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        import time
        cursor.execute('''
            UPDATE room_members 
            SET is_online = ?, last_seen = ?
            WHERE room_id = ? AND username = ?
        ''', (1 if is_online else 0, int(time.time()), room_id, username))
        
        conn.commit()
        return True
    except Exception as e:
        print(f"[DB] Error updating online status: {e}")
        return False

def transfer_admin(room_id: str, new_admin: str) -> bool:
    """
    Transfer admin role to another user in the room.
    
    Changes a user's role from 'member' to 'admin'. Used when the current
    admin leaves the room to ensure continuity of room management.
    
    Args:
        room_id (str): Room to transfer admin in
        new_admin (str): Username to promote to admin
    
    Returns:
        bool: True if transfer successful, False otherwise
    
    Note:
        Does not demote the old admin - caller must handle that separately
        if needed (typically by removing them from the room).
    """
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
    """
    Find the next user to become admin based on seniority.
    
    Selects the member who joined earliest (excluding the specified user),
    following a "first come, first serve" promotion policy.
    
    Args:
        room_id (str): Room to find next admin for
        exclude (str): Username to exclude from selection (typically current admin)
    
    Returns:
        str or None: Username of next admin candidate, None if no other members
    
    Example:
        >>> next_admin = get_next_admin("room_123", "alice")
        >>> print(f"Promote {next_admin} to admin")
    """
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
    """
    Save an encrypted message to the database.
    
    Stores the encrypted message content along with metadata including which
    encryption key version was used. This allows clients to decrypt messages
    even after key rotation events. Supports multiple file attachments.
    
    Args:
        room_id (str): Room the message belongs to
        sender (str): Username of message sender
        encrypted_content (str): Hex-encoded encrypted message (IV + ciphertext)
        key_version (int): Version of room key used for encryption. Defaults to 0
        file_metadata (dict or str, optional): Single file attachment dict, 
                                               JSON string of file array, or None
    
    Returns:
        int: Unique message ID (auto-incremented)
    
    Note:
        The key_version field is CRITICAL for decryption after key rotation.
        Clients use this to select the correct historical key for decryption.
    """
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
    """
    Get encrypted messages for a room based on user's access history.
    
    Retrieves messages that occurred after the user's first_join_at timestamp,
    ensuring users only see messages from periods when they were members.
    Includes reactions and file metadata for each message.
    
    Args:
        room_id (str): Room to get messages from
        user_first_join (float): Unix timestamp of user's first join
        limit (int): Maximum messages to return. Defaults to 50
        before_id (int, optional): Get messages before this ID (for pagination)
    
    Returns:
        list: Messages in reverse chronological order (newest first unless reversed),
              each containing: id, sender, encrypted_content, timestamp, key_version,
              reactions (dict), file_metadata (dict or None)
    
    Note:
        The before_id parameter enables "load more" functionality for infinite scroll.
    """
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
    
    # Order by ID DESC to get NEWEST messages first
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
    
    # Reverse to show oldest-to-newest for display
    return list(reversed(messages))

def delete_message(message_id: int, deleted_by: str) -> bool:
    """
    Soft-delete a message (mark as deleted without removing record).
    
    Sets deleted=1 flag and records who deleted it and when. The encrypted
    content remains in the database but clients display "[Message deleted]".
    
    Args:
        message_id (int): Message ID to delete
        deleted_by (str): Username of person deleting (for audit trail)
    
    Returns:
        bool: True if deletion successful, False otherwise
    
    Note:
        This is a soft delete - the record persists for data integrity and
        potential recovery. Reactions are preserved.
    """
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

def get_message_sender(message_id: int) -> Optional[Dict]:
    """
    Get the sender and room_id of a specific message.
    
    Used for authorization checks before allowing message deletion.
    Only the sender, room admins, or global admins can delete messages.
    
    Args:
        message_id (int): Message to lookup
    
    Returns:
        dict or None: {'sender': username, 'room_id': room_id}
                      Returns None if message doesn't exist
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT sender, room_id FROM messages WHERE id = ?', (message_id,))
    row = cursor.fetchone()
    return dict(row) if row else None

# ===== REACTION OPERATIONS =====

def add_reaction(message_id: int, username: str, emoji: str) -> bool:
    """
    Add an emoji reaction to a message.
    
    Creates a reaction record linking a user to a message with an emoji.
    Uses INSERT OR IGNORE to prevent duplicate reactions (same user can't
    react with the same emoji multiple times).
    
    Args:
        message_id (int): Message to react to
        username (str): User adding the reaction
        emoji (str): Emoji character (e.g., "👍", "❤️", "😂")
    
    Returns:
        bool: True if reaction added (or already existed), False on error
    
    Note:
        A user can add multiple different emojis to the same message,
        but can't add the same emoji twice.
    """
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
    """
    Remove a user's emoji reaction from a message.
    
    Deletes the reaction record, allowing the user to "un-react".
    
    Args:
        message_id (int): Message to remove reaction from
        username (str): User removing their reaction
        emoji (str): Emoji to remove
    
    Returns:
        bool: True if removal successful, False otherwise
    
    Note:
        Silently succeeds even if the reaction didn't exist.
    """
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
    """
    Get all reactions for a message grouped by emoji.
    
    Retrieves and organizes reactions into a dict mapping each emoji to
    a list of usernames who used that emoji.
    
    Args:
        message_id (int): Message to get reactions for
    
    Returns:
        dict: {emoji: [username1, username2, ...]}
              Empty dict if no reactions
    
    Example:
        >>> reactions = get_message_reactions(42)
        >>> print(reactions)
        {'👍': ['alice', 'bob'], '❤️': ['charlie']}
    """
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

def remove_user_reactions(room_id: str, username: str) -> bool:
    """
    Remove all reactions from a specific user in a specific room.
    
    Called when a user leaves or is kicked from a room to clean up
    their reaction records. This prevents ghost reactions from users
    who are no longer members.
    
    Args:
        room_id (str): Room to remove reactions from
        username (str): User whose reactions to remove
    
    Returns:
        bool: True if removal successful, False otherwise
    
    Note:
        This maintains data integrity by ensuring only active members
        can have reactions visible on messages.
    """
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Get all message IDs in this room
        cursor.execute('''
            SELECT id FROM messages WHERE room_id = ?
        ''', (room_id,))
        message_ids = [row['id'] for row in cursor.fetchall()]
        
        # Remove user's reactions from all messages in this room
        if message_ids:
            placeholders = ','.join('?' * len(message_ids))
            cursor.execute(f'''
                DELETE FROM reactions 
                WHERE message_id IN ({placeholders}) AND username = ?
            ''', message_ids + [username])
        
        conn.commit()
        return True
    except Exception as e:
        print(f"[DB] Error removing user reactions: {e}")
        return False

# ===== REPORT OPERATIONS =====

def create_report(room_id: str, reporter: str, reason: str, details: str = '', evidence_file: str = None) -> int:
    """
    Create a moderation report for a room.
    
    Allows users to report rooms for violations (spam, harassment, etc.).
    Reports are created with 'pending' status for global admin review.
    Can include multiple evidence files stored as JSON array.
    
    Args:
        room_id (str): Room being reported
        reporter (str): Username of person filing report
        reason (str): Short reason for report (e.g., "Spam", "Harassment")
        details (str): Optional detailed explanation. Defaults to empty
        evidence_file (str, optional): JSON string containing array of evidence file paths,
                                      or single path string for backward compatibility
    
    Returns:
        int: Unique report ID
    
    Note:
        Multiple reports can exist for the same room from different users.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO reports (room_id, reporter, reason, details, timestamp, evidence_file)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (room_id, reporter, reason, details, datetime.now().timestamp(), evidence_file))
    report_id = cursor.lastrowid
    conn.commit()
    return report_id
    
def get_pending_reports() -> List[Dict]:
    """
    Get all unresolved moderation reports for global admin review.
    
    Retrieves reports with status='pending' joined with room names,
    ordered by submission time (newest first).
    
    Returns:
        list: Reports with fields: id, room_id, room_name, reporter, reason,
              details, timestamp, status, resolved_by, resolved_at
    
    Note:
        Only accessible to global admins. Used for the admin moderation panel.
    """
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
    """
    Mark a moderation report as resolved.
    
    Updates report status and records who resolved it and when.
    Typically called after admin takes action (deletes room or dismisses report).
    
    Args:
        report_id (int): Report to resolve
        resolved_by (str): Admin username resolving the report
        status (str): New status. Defaults to 'resolved'
    
    Returns:
        bool: True if update successful, False otherwise
    
    Note:
        Resolving a report doesn't automatically delete the reported room -
        admin must do that separately if needed.
    """
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
    """
    Update room's basic information (name, description, capacity).
    
    Allows room admins to modify room settings. Name must still be unique.
    
    Args:
        room_id (str): Room to update
        name (str): New room name (must be unique across system)
        description (str): New description
        max_members (int): New maximum capacity
    
    Returns:
        bool: True if update successful, False if name conflict or error
    
    Note:
        Does NOT update password or access control settings - use
        update_room_password() for that.
    """
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
    """
    Update or remove a room's password.
    
    Changes the password_hash for a private room. Can set to None to
    remove password protection (invite code still required for private rooms).
    
    Args:
        room_id (str): Room to update
        password_hash (str or None): Bcrypt hash of new password, or None to remove
    
    Returns:
        bool: True if update successful, False otherwise
    
    Note:
        Only affects private rooms. Public rooms ignore password_hash field.
        Always pass a bcrypt hash, never a plaintext password.
    """
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

def update_room_type(room_id: str, new_type: str, password_hash: Optional[str] = None, 
                     invite_code: Optional[str] = None) -> bool:
    """
    Update a room's type between public and private.
    
    When switching to private, generates invite code and optionally sets password.
    When switching to public, removes password and invite code.
    
    Args:
        room_id (str): Room to update
        new_type (str): 'public' or 'private'
        password_hash (str, optional): Bcrypt hash for private rooms
        invite_code (str, optional): Invite code for private rooms
    
    Returns:
        bool: True if update successful, False otherwise
    
    Note:
        Switching to public removes all access control (password + invite code).
        Switching to private requires generating new invite code.
    """
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        if new_type == 'public':
            # Remove access control when switching to public
            cursor.execute('''
                UPDATE rooms 
                SET type = ?, password_hash = NULL, invite_code = NULL 
                WHERE id = ?
            ''', (new_type, room_id))
        else:  # private
            # Add access control when switching to private
            cursor.execute('''
                UPDATE rooms 
                SET type = ?, password_hash = ?, invite_code = ? 
                WHERE id = ?
            ''', (new_type, password_hash, invite_code, room_id))
        
        conn.commit()
        return True
    except Exception as e:
        print(f"[DB] Error updating room type: {e}")
        return False

def find_room_by_invite_code(invite_code: str) -> Optional[Dict]:
    """
    Find a private room by its invite code.
    
    Looks up a room using the unique invite code, returning room details
    with member count. Sanitizes output to hide password_hash (only indicates
    if password exists).
    
    Args:
        invite_code (str): Invite code to search for
    
    Returns:
        dict or None: Room data with 'has_password' boolean flag
                      Returns None if invite code not found
    
    Note:
        Used when users paste an invite link to join a private room.
    """
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
    """
    Search public rooms by name (case-insensitive partial match).
    
    Performs LIKE query on public room names, returning matches with
    member counts. Used for the room search feature in the hub.
    
    Args:
        query (str): Search term (case-insensitive, matches anywhere in name)
    
    Returns:
        list: Matching rooms with member_count field
              Empty list if no matches
    
    Example:
        >>> rooms = search_rooms_by_name("tech")
        >>> # Returns "Tech Talk", "Technology", "FinTech", etc.
    """
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

def get_messages_after_timestamp(room_id: str, timestamp: float, limit: int = 50) -> List[Dict]:
    """
    Retrieve encrypted messages from a room after a specific timestamp.
    
    Used to send message history to users based on their first_join_at timestamp.
    Includes reactions and file metadata for each message.
    
    Args:
        room_id (str): Room to get messages from
        timestamp (float): Unix timestamp - only return messages after this time
        limit (int): Maximum number of messages to return. Defaults to 50
    
    Returns:
        list: Messages in chronological order (oldest first), each containing:
              - id, sender, encrypted_content, timestamp, key_version
              - reactions: dict of {emoji: [usernames]}
              - file_metadata: dict or None
    
    Note:
        Does not filter by key version - users who stayed through key rotation
        should receive all messages they had access to, regardless of which key
        was used for encryption.
    """
    conn = get_db()
    cursor = conn.cursor()
    
    query = '''
        SELECT m.*, GROUP_CONCAT(r.emoji || ':' || r.username, '|') as reactions
        FROM messages m
        LEFT JOIN reactions r ON m.id = r.message_id
        WHERE m.room_id = ? AND m.timestamp >= ? AND m.deleted = 0
        GROUP BY m.id
        ORDER BY m.id DESC
        LIMIT ?
    '''
    
    cursor.execute(query, (room_id, timestamp, limit))
    rows = cursor.fetchall()
    
    messages = []
    for row in rows:
        msg = dict(row)
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
        
        if msg['file_metadata']:
            msg['file_metadata'] = json.loads(msg['file_metadata'])
        
        messages.append(msg)
    
    # Reverse to show oldest-to-newest for display
    return list(reversed(messages))

def migrate_add_online_status():
    """
    Add online status tracking columns to members table.
    
    Adds two new columns:
    - is_online: INTEGER (1=online, 0=offline)
    - last_seen: REAL (Unix timestamp of last activity)
    
    Safe to run multiple times - checks if columns already exist.
    """
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Check if column exists
        cursor.execute("PRAGMA table_info(room_members)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'is_online' not in columns:
            print("[DB] Adding online status columns to room_members table...")
            cursor.execute('ALTER TABLE room_members ADD COLUMN is_online INTEGER DEFAULT 0')
            cursor.execute('ALTER TABLE room_members ADD COLUMN last_seen INTEGER DEFAULT 0')
            conn.commit()
            print("[DB] ✅ Online status columns added successfully")
        else:
            print("[DB] ✅ Online status columns already exist")
    except Exception as e:
        print(f"[DB] Migration error: {e}")

def get_room_snapshot(room_id: str) -> Dict:
    """
    Get a comprehensive snapshot of a room for admin review.
    
    Returns recent activity including messages, members, and metadata.
    Used by global admins when reviewing reports to see room context
    without joining the room.
    
    Args:
        room_id (str): Room to get snapshot for
    
    Returns:
        dict: {
            'room_info': Room details,
            'members': List of members with roles,
            'recent_messages': Last 10 messages (metadata only - encrypted),
            'member_count': Current member count,
            'message_count': Total message count
        }
    
    Note:
        Messages are still encrypted - admin sees metadata only
        (sender, timestamp, has_file) but cannot read content.
        This preserves E2EE while allowing moderation.
    """
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Get room info
        room_info = get_room(room_id)
        if not room_info:
            return None
        
        # Get members
        members = get_room_members(room_id)
        
        return {
            'room_info': room_info,
            'members': members,
            'member_count': len(members)
        }
    except Exception as e:
        print(f"[DB] Error getting room snapshot: {e}")
        return None

def get_room_report_history(room_id: str) -> Dict:
    """
    Get complete report history for a room.
    
    Returns all reports (pending and resolved) for admin review,
    showing patterns of abuse and moderation history.
    
    Args:
        room_id (str): Room to get history for
    
    Returns:
        dict: {
            'total_reports': int,
            'pending_reports': int,
            'resolved_reports': int,
            'reports': list of all reports with details,
            'first_report_date': timestamp or None,
            'last_report_date': timestamp or None,
            'risk_level': str ('HIGH', 'MEDIUM', 'LOW')
        }
    """
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Get all reports for this room
        cursor.execute('''
            SELECT * FROM reports 
            WHERE room_id = ?
            ORDER BY timestamp DESC
        ''', (room_id,))
        
        reports = [dict(row) for row in cursor.fetchall()]
        
        if not reports:
            return {
                'total_reports': 0,
                'pending_reports': 0,
                'resolved_reports': 0,
                'reports': [],
                'first_report_date': None,
                'last_report_date': None,
                'risk_level': 'LOW'
            }
        
        # Count by status
        pending = [r for r in reports if r['status'] == 'pending']
        resolved = [r for r in reports if r['status'] == 'resolved']
        
        # Get recent reports (last 7 days)
        import time
        seven_days_ago = time.time() - (7 * 24 * 60 * 60)
        recent_reports = [r for r in reports if r['timestamp'] > seven_days_ago]
        
        # Calculate risk level based on report patterns
        if len(recent_reports) >= 5:
            risk_level = 'HIGH'
        elif len(recent_reports) >= 2 or len(pending) >= 2:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'total_reports': len(reports),
            'pending_reports': len(pending),
            'resolved_reports': len(resolved),
            'reports': reports,
            'first_report_date': reports[-1]['timestamp'],  # Oldest
            'last_report_date': reports[0]['timestamp'],   # Newest
            'risk_level': risk_level,
            'recent_reports_7d': len(recent_reports)
        }
        
    except Exception as e:
        print(f"[DB] Error getting report history: {e}")
        return None

def migrate_add_report_evidence():
    """
    Add evidence attachment support to reports table.
    
    Adds column:
    - evidence_file: TEXT (path to uploaded evidence file)
    
    Safe to run multiple times - checks if column already exists.
    """
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Check if column exists
        cursor.execute("PRAGMA table_info(reports)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'evidence_file' not in columns:
            print("[DB] Adding evidence_file column to reports table...")
            cursor.execute('ALTER TABLE reports ADD COLUMN evidence_file TEXT')
            conn.commit()
            print("[DB] ✅ Evidence column added successfully")
        else:
            print("[DB] ✅ Evidence column already exists")
    except Exception as e:
        print(f"[DB] Migration error: {e}")

def update_room_creator(room_id: str, new_creator: str) -> bool:
    """
    Update the creator/owner field for a room.
    
    Used when room ownership transfers to ensure the hub displays
    the correct current owner, not the original creator.
    
    Args:
        room_id (str): Room to update
        new_creator (str): New owner username
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE rooms SET creator = ? WHERE id = ?
        ''', (new_creator, room_id))
        conn.commit()
        return True
    except Exception as e:
        print(f"[DB] Error updating room creator: {e}")
        return False

def get_user_room_ids(username: str) -> list:
    """
    Get list of room IDs that a user is a member of.
    
    Args:
        username (str): Username to lookup
    
    Returns:
        list: List of room_id strings
    """
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT DISTINCT room_id 
            FROM room_members 
            WHERE username = ?
        ''', (username,))
        
        return [row['room_id'] for row in cursor.fetchall()]
    except Exception as e:
        print(f"[ERROR] Failed to get user room IDs: {e}")
        return []

def delete_user_data_gdpr(username: str) -> dict:
    """
    Delete ALL data associated with a user (GDPR compliance).
    
    Removes:
    - All messages sent by user
    - All reactions by user
    - All room memberships (and transfers room ownership if needed)
    - All reports filed by user
    - All uploaded files by user
    
    Args:
        username (str): Username to delete data for
    
    Returns:
        dict: Statistics about what was deleted including deleted_rooms list
    """
    conn = get_db()
    cursor = conn.cursor()
    
    stats = {
        'messages_deleted': 0,
        'reactions_deleted': 0,
        'memberships_deleted': 0,
        'reports_deleted': 0,
        'files_deleted': 0,
        'evidence_deleted': 0,
        'rooms_transferred': 0,
        'deleted_rooms': []  # Track which rooms were deleted
    }
    
    try:
        from pathlib import Path
        import json
        import glob
        
        upload_folder = Path(__file__).parent / 'uploads'
        
        # STEP 1: COUNT EVERYTHING FIRST (before any deletions)
        cursor.execute('SELECT COUNT(*) FROM messages WHERE sender = ?', (username,))
        stats['messages_deleted'] = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM reactions WHERE username = ?', (username,))
        stats['reactions_deleted'] = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM room_members WHERE username = ?', (username,))
        stats['memberships_deleted'] = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM reports WHERE reporter = ?', (username,))
        stats['reports_deleted'] = cursor.fetchone()[0]
        
        # STEP 2: DELETE UPLOADED FILES
        print(f"[GDPR] Looking for files uploaded by {username}...")
        cursor.execute('''
            SELECT id, file_metadata 
            FROM messages 
            WHERE sender = ? AND file_metadata IS NOT NULL
        ''', (username,))

        file_rows = cursor.fetchall()
        print(f"[GDPR] Found {len(file_rows)} messages with file metadata")

        for row in file_rows:
            try:
                file_metadata_raw = row['file_metadata']
                print(f"[GDPR] Message {row['id']} raw metadata type: {type(file_metadata_raw)}")
                
                # CRITICAL: SQLite stores JSON as STRING, so we need to parse it
                files = json.loads(file_metadata_raw)
                print(f"[GDPR] After 1st parse, type: {type(files)}")
                
                # Handle different formats
                if isinstance(files, str):
                    # It's STILL a string - parse again!
                    # This happens when JSON is double-encoded
                    print(f"[GDPR] Still string after 1st parse, parsing again...")
                    try:
                        files = json.loads(files)
                        print(f"[GDPR] After 2nd parse, type: {type(files)}")
                    except:
                        # Really is just a plain string (old format)
                        print(f"[GDPR] Plain string (no JSON): {files[:50]}...")
                        continue
                
                elif isinstance(files, dict):
                    # Single file dict format
                    print(f"[GDPR] Single file dict format")
                    files = [files]
                
                elif isinstance(files, list):
                    # Multiple files array format (correct format)
                    print(f"[GDPR] Array format with {len(files)} files")
                
                else:
                    print(f"[GDPR] Unknown format: {type(files)}")
                    continue
                
                # Now files should be a list of dicts
                for idx, file_info in enumerate(files):
                    if not isinstance(file_info, dict):
                        print(f"[GDPR] File {idx} is not a dict: {type(file_info)}")
                        continue
                    
                    file_id = file_info.get('file_id')
                    filename = file_info.get('filename', 'unknown')
                    
                    if not file_id:
                        print(f"[GDPR] No file_id in file {idx}")
                        continue
                    
                    print(f"[GDPR] Looking for file_id: {file_id}, filename: {filename}")
                    
                    # Find and delete the file
                    search_pattern = str(upload_folder / f"{file_id}_*")
                    matching_files = glob.glob(search_pattern)
                    
                    print(f"[GDPR] Search pattern: {search_pattern}")
                    print(f"[GDPR] Found {len(matching_files)} matching files")
                    
                    for file_path in matching_files:
                        try:
                            Path(file_path).unlink()
                            stats['files_deleted'] += 1
                            print(f"[GDPR] ✓ Deleted: {file_path}")
                        except Exception as e:
                            print(f"[GDPR] ✗ Failed to delete {file_path}: {e}")
                
            except json.JSONDecodeError as e:
                print(f"[GDPR] JSON decode error for message {row['id']}: {e}")
            except Exception as e:
                print(f"[GDPR] Error processing message {row['id']}: {e}")
                import traceback
                traceback.print_exc()

        print(f"[GDPR] Total files deleted: {stats['files_deleted']}")
        
        # STEP 3: TRANSFER ROOM OWNERSHIP OR DELETE EMPTY ROOMS
        cursor.execute('''
            SELECT DISTINCT room_id 
            FROM room_members 
            WHERE username = ? AND role = 'admin'
        ''', (username,))
        
        admin_rooms = [row['room_id'] for row in cursor.fetchall()]
        print(f"[GDPR] User is admin of {len(admin_rooms)} rooms")
        
        for room_id in admin_rooms:
            # Get other members
            cursor.execute('''
                SELECT username, joined_at 
                FROM room_members 
                WHERE room_id = ? AND username != ?
                ORDER BY joined_at ASC
            ''', (room_id, username))
            
            other_members = cursor.fetchall()
            
            if other_members:
                # Transfer ownership to oldest member
                new_admin = other_members[0]['username']
                
                # Update member role
                cursor.execute('''
                    UPDATE room_members 
                    SET role = 'admin' 
                    WHERE room_id = ? AND username = ?
                ''', (room_id, new_admin))
                
                # IMPORTANT: Update room creator so hub shows correct owner
                cursor.execute('''
                    UPDATE rooms 
                    SET creator = ? 
                    WHERE id = ?
                ''', (new_admin, room_id))
                
                stats['rooms_transferred'] += 1
                print(f"[GDPR] Transferred {room_id} ownership: {username} → {new_admin}")
            else:
                # No other members - delete the room entirely
                print(f"[GDPR] Deleting empty room: {room_id}")
                
                # Delete room and cascade deletes messages/reactions
                cursor.execute('DELETE FROM rooms WHERE id = ?', (room_id,))
                
                # Track deleted room for broadcast
                stats['deleted_rooms'].append(room_id)
                
                print(f"[GDPR] ✓ Deleted empty room: {room_id}")
        
        # STEP 4: DELETE MESSAGES (not already deleted by room cascade)
        cursor.execute('DELETE FROM messages WHERE sender = ?', (username,))
        print(f"[GDPR] Deleted {stats['messages_deleted']} messages")
        
        # STEP 5: DELETE REACTIONS
        cursor.execute('DELETE FROM reactions WHERE username = ?', (username,))
        print(f"[GDPR] Deleted {stats['reactions_deleted']} reactions")
        
        # STEP 6: DELETE MEMBERSHIPS
        cursor.execute('DELETE FROM room_members WHERE username = ?', (username,))
        print(f"[GDPR] Deleted {stats['memberships_deleted']} memberships")
        
        # STEP 7: DELETE EVIDENCE IMAGES (BEFORE deleting reports!)
        print(f"[GDPR] Deleting evidence images...")
        cursor.execute('''
            SELECT evidence_file 
            FROM reports 
            WHERE reporter = ? AND evidence_file IS NOT NULL
        ''', (username,))

        evidence_rows = cursor.fetchall()
        evidence_deleted = 0

        for row in evidence_rows:
            try:
                evidence_file = row['evidence_file']
                
                # Handle both formats: JSON array or single string
                try:
                    evidence_files = json.loads(evidence_file)
                    if not isinstance(evidence_files, list):
                        evidence_files = [evidence_file]
                except:
                    evidence_files = [evidence_file]
                
                # Delete each evidence file from disk
                evidence_folder = Path(__file__).parent / 'uploads' / 'evidence'
                for evidence_path in evidence_files:
                    # Extract filename from path (format: "evidence/evidence_xxxxx.png")
                    filename = evidence_path.split('/')[-1]
                    full_path = evidence_folder / filename
                    
                    if full_path.exists():
                        full_path.unlink()
                        evidence_deleted += 1
                        print(f"[GDPR] ✓ Deleted evidence: {filename}")
                    else:
                        print(f"[GDPR] ⚠ Evidence not found: {filename}")
                        
            except Exception as e:
                print(f"[GDPR] ✗ Error deleting evidence: {e}")

        stats['evidence_deleted'] = evidence_deleted
        print(f"[GDPR] Deleted {evidence_deleted} evidence images")

        # STEP 8: DELETE REPORTS (AFTER deleting their evidence files)
        cursor.execute('DELETE FROM reports WHERE reporter = ?', (username,))
        print(f"[GDPR] Deleted {stats['reports_deleted']} reports")
        
        conn.commit()
        print(f"[GDPR] ✓ All data deleted for {username}")
        return stats
        
    except Exception as e:
        conn.rollback()
        print(f"[ERROR] GDPR delete failed: {e}")
        import traceback
        traceback.print_exc()
        return stats

def export_user_data_gdpr(username: str) -> dict:
    """
    Export ALL user data with full encrypted message content (GDPR compliance).
    
    Returns ENCRYPTED messages with key_version so client can decrypt using
    keys from localStorage. This is TRUE E2EE - server never sees plaintext.
    
    Args:
        username (str): Username to export data for
    
    Returns:
        dict: All user data in JSON-friendly format with encrypted messages
    """
    conn = get_db()
    cursor = conn.cursor()
    
    data = {
        'username': username,
        'export_date': datetime.now().isoformat(),
        'messages': [],
        'reactions': [],
        'room_memberships': [],
        'reports_filed': []
    }
    
    try:
        # Get all messages WITH FULL encrypted content for client-side decryption
        cursor.execute('''
            SELECT m.id, m.room_id, r.name as room_name, m.sender, 
                   m.encrypted_content, m.timestamp, m.key_version, m.file_metadata
            FROM messages m
            JOIN rooms r ON m.room_id = r.id
            WHERE m.sender = ? AND m.deleted = 0
            ORDER BY m.timestamp DESC
        ''', (username,))
        
        for row in cursor.fetchall():
            # Include FULL encrypted content so client can decrypt
            msg_data = {
                'message_id': row['id'],
                'room_id': row['room_id'],
                'room_name': row['room_name'],
                'timestamp': datetime.fromtimestamp(row['timestamp']).isoformat(),
                'encrypted_content': row['encrypted_content'],  # FULL encrypted hex
                'key_version': row['key_version'],  # Client needs this to pick correct key
                'files': json.loads(row['file_metadata']) if row['file_metadata'] else []
            }
            data['messages'].append(msg_data)
        
        # Get all reactions
        cursor.execute('''
            SELECT r.emoji, m.id as message_id, rm.name as room_name, r.timestamp
            FROM reactions r
            JOIN messages m ON r.message_id = m.id
            JOIN rooms rm ON m.room_id = rm.id
            WHERE r.username = ?
            ORDER BY r.timestamp DESC
        ''', (username,))
        
        for row in cursor.fetchall():
            data['reactions'].append({
                'emoji': row['emoji'],
                'room': row['room_name'],
                'timestamp': datetime.fromtimestamp(row['timestamp']).isoformat()
            })
        
        # Get room memberships
        cursor.execute('''
            SELECT rm.room_id, r.name, rm.role, rm.joined_at, rm.first_join_at
            FROM room_members rm
            JOIN rooms r ON rm.room_id = r.id
            WHERE rm.username = ?
            ORDER BY rm.joined_at DESC
        ''', (username,))
        
        for row in cursor.fetchall():
            data['room_memberships'].append({
                'room_id': row['room_id'],
                'room_name': row['name'],
                'role': row['role'],
                'joined_at': datetime.fromtimestamp(row['joined_at']).isoformat(),
                'first_joined_at': datetime.fromtimestamp(row['first_join_at']).isoformat()
            })
        
        # Get reports filed
        cursor.execute('''
            SELECT rep.id, r.name as room_name, rep.reason, rep.details, 
                   rep.timestamp, rep.status
            FROM reports rep
            JOIN rooms r ON rep.room_id = r.id
            WHERE rep.reporter = ?
            ORDER BY rep.timestamp DESC
        ''', (username,))
        
        for row in cursor.fetchall():
            data['reports_filed'].append({
                'report_id': row['id'],
                'room': row['room_name'],
                'reason': row['reason'],
                'details': row['details'],
                'timestamp': datetime.fromtimestamp(row['timestamp']).isoformat(),
                'status': row['status']
            })
        
        return data
        
    except Exception as e:
        print(f"[ERROR] GDPR export failed: {e}")
        return data

# Initialize database on import
init_db()
migrate_add_online_status()
migrate_add_report_evidence()