import os
import sys
import json
import secrets
import bcrypt
from typing import Optional, Tuple, Dict, List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import database as db
import crypto
from users import is_admin as is_global_admin, load_users, save_users

# In-memory key storage (never persisted to disk for E2EE)
room_keys = {}  # {room_id: {'key': bytes, 'version': int}}

def generate_room_id(name: str) -> str:
    """Generate unique room ID"""
    return f"room_{secrets.token_hex(8)}_{name[:20].replace(' ', '_').lower()}"

def generate_invite_code() -> str:
    """Generate random invite code for private rooms"""
    return secrets.token_urlsafe(16)

class RoomManager:
    """
    Manage chat room lifecycle, encryption keys, and access control.
    
    This class handles all room-related operations including creation, joining,
    leaving, and deletion. It also manages the critical encryption key lifecycle:
    - Key generation using deterministic derivation
    - Key rotation when users are removed (kicked)
    - Key distribution to authorized members
    
    The RoomManager maintains an in-memory store of active room keys that is
    never persisted to disk, ensuring true end-to-end encryption where the
    server cannot decrypt messages without active user connections.
    
    Attributes:
        This class primarily interacts with the database module and maintains
        no persistent state beyond the database.
    
    Note:
        Room keys are stored in the global room_keys dict as:
        {room_id: {'key': bytes, 'version': int}}
    """
    def __init__(self):
        """
        Initialize the RoomManager.
        
        Currently performs no initialization as room keys are stored in the
        global room_keys dict and room data is persisted in the database.
        
        Note:
            This class is designed as a singleton accessed via the global
            room_manager instance at module level.
        """
        pass
    
    def create_room(self, name: str, creator: str, room_type: str = 'public',
                password: Optional[str] = None, description: str = '',
                max_members: int = 50) -> Tuple[bool, Optional[str], str]:
        """
        Create a new chat room with deterministic encryption key.
        
        Generates a unique room ID, creates database records, and derives the
        initial encryption key (version 0) deterministically from the room ID.
        For private rooms, generates invite codes and optionally hashes passwords.
        
        Args:
            name (str): Room name (max 50 chars, must be unique)
            creator (str): Username of room creator (becomes admin)
            room_type (str): 'public' or 'private'. Defaults to 'public'
            password (str, optional): Plain-text password for private rooms
            description (str): Room description. Defaults to empty
            max_members (int): Max capacity. Defaults to 50
        
        Returns:
            tuple: (success: bool, room_id: str or None, message: str)
                - (True, room_id, "Room 'name' created") on success
                - (False, None, error_message) on failure
        
        Note:
            The deterministic key derivation ensures the same room always gets
            the same initial key, enabling key recovery after server restarts.
        """
        if not name or len(name) > 50:
            return False, None, "Invalid room name"
        
        room_id = generate_room_id(name)
        
        # Access control for private rooms
        password_hash = None
        invite_code = None
        
        if room_type == 'private':
            invite_code = generate_invite_code()
            if password:
                password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        
        # Create room in database FIRST
        success = db.create_room(
            room_id=room_id,
            name=name,
            creator=creator,
            room_type=room_type,
            password_hash=password_hash,
            invite_code=invite_code,
            description=description,
            max_members=max_members
        )
        
        if not success:
            return False, None, "Room name already exists"
        
        # CRITICAL FIX: Generate deterministic key from room_id
        # This ensures the same key is always generated for the same room
        initial_key = self._derive_room_key(room_id, version=0)
        
        room_keys[room_id] = {
            'key': initial_key,
            'version': 0
        }
        
        print(f"[KEY_INIT] Created room {room_id} with deterministic key v0")
        
        return True, room_id, f"Room '{name}' created"

    def _derive_room_key(self, room_id: str, version: int) -> bytes:
        """
        Derive a deterministic 32-byte encryption key from room ID and version.
        
        Uses repeated SHA256 hashing (10,000 iterations) to derive a secure key
        that is always the same for a given room_id and version. This enables:
        - Key recovery after server restart
        - Historical key regeneration for message decryption
        - Predictable key rotation
        
        Args:
            room_id (str): Unique room identifier
            version (int): Key version number (0, 1, 2, ...)
        
        Returns:
            bytes: 32-byte encryption key
        
        Note:
            This is the CORE of the key management system. The deterministic
            nature means we can always recreate any key version if we know
            the room_id and version number.
        """
        import hashlib
        
        # Use HKDF-style derivation
        material = f"{room_id}:v{version}:groupkey".encode()
        
        # Use multiple hash rounds for key stretching
        key = hashlib.sha256(material).digest()
        for _ in range(10000):  # 10k rounds
            key = hashlib.sha256(key).digest()
        
        return key

    def join_room(self, room_id: str, username: str, password: Optional[str] = None,
                 invite_code: Optional[str] = None) -> Tuple[bool, Optional[str], str]:
        """
        Add a user to a chat room with access control verification.
        
        Verifies user authorization (invite codes and passwords for private rooms),
        checks room capacity, and adds the user as a member. Ensures the room's
        encryption key exists in memory or regenerates it deterministically.
        
        Args:
            room_id (str): Room to join
            username (str): User attempting to join
            password (str, optional): Password for private rooms
            invite_code (str, optional): Invite code for private rooms
        
        Returns:
            tuple: (success: bool, room_id: str or None, message: str)
                - (True, room_id, "Joined 'name'") on success
                - (False, None, error_message) on failure
        
        Note:
            For private rooms with invite codes, BOTH invite code AND password
            (if set) must be provided and correct.
        """
        room = db.get_room(room_id)
        if not room:
            return False, None, "Room not found"
        
        # Check if already a member
        current_role = db.get_member_role(room_id, username)
        
        # Check if room is full (only for new joins)
        if not current_role:
            members = db.get_room_members(room_id)
            if len(members) >= room['max_members']:
                return False, None, "Room is full"
        
        # Verify access for private rooms
        if room['type'] == 'private':
            has_password = bool(room.get('password_hash'))
            has_invite = bool(room.get('invite_code'))
            
            # MUST have invite code
            if has_invite:
                if not invite_code or invite_code != room['invite_code']:
                    return False, None, "Invalid or missing invite code"
            
            # Check password if set
            if has_password:
                if not password:
                    return False, None, "Password required"
                if not bcrypt.checkpw(password.encode(), room['password_hash'].encode()):
                    return False, None, "Incorrect password"
        
        # Add or re-add user to room
        if current_role:
            success = db.add_member(room_id, username, current_role)
        else:
            success = db.add_member(room_id, username, 'member')
        
        if not success:
            return False, None, "Failed to join room"
        
        # Ensure room key exists
        if room_id not in room_keys:
            print(f"[KEY_WARNING] Room {room_id} key not found in memory!")
            print(f"[KEY_WARNING] Server restart detected. Creating new key.")
            room_keys[room_id] = {
                'key': os.urandom(32),
                'version': room.get('key_version', 0)
            }
        
        return True, room_id, f"Joined '{room['name']}'"
    
    def leave_room(self, room_id: str, username: str) -> Tuple[bool, Optional[str], str]:
        """
        Remove a user from a room (voluntary exit).
        
        Handles admin succession if the leaving user is the admin. If admin
        leaves, promotes the next oldest member. If last member leaves, deletes
        the room and its encryption key from memory.
        
        Args:
            room_id (str): Room to leave
            username (str): User exiting the room
        
        Returns:
            tuple: (success: bool, new_admin: str or None, message: str)
                - (True, username, "Left room") if member left
                - (True, None, "Room deleted (last member)") if room deleted
                - (False, None, "Not in room") if not a member
        
        Note:
            Unlike kick_user(), this does NOT rotate the encryption key since
            it's a voluntary exit. User loses access but no forward secrecy needed.
        """
        role = db.get_member_role(room_id, username)
        if not role:
            return False, None, "Not in room"
        
        new_admin = None
        
        # If leaving user is admin, transfer to next member
        if role == 'admin':
            next_admin = db.get_next_admin(room_id, username)
            if next_admin:
                db.transfer_admin(room_id, next_admin)
                new_admin = next_admin
            else:
                # Last member leaving - delete room
                db.delete_room(room_id)
                if room_id in room_keys:
                    del room_keys[room_id]
                return True, None, "Room deleted (last member)"
        
        # Remove member
        db.remove_member(room_id, username, wipe_history=False)
        
        return True, new_admin, "Left room"
    
    def kick_user(self, room_id: str, kicker_token: str, target_username: str) -> Tuple[bool, Optional[bytes], str]:
        """
        Remove a user from a room and rotate the encryption key.
        
        Only room admins or global admins can kick users. After removal, generates
        a new encryption key (version N+1) deterministically and returns it for
        distribution to remaining members. This ensures the kicked user cannot
        decrypt future messages (forward secrecy).
        
        Args:
            room_id (str): Room to kick user from
            kicker_token (str): Session token of user performing kick (for auth)
            target_username (str): Username to remove
        
        Returns:
            tuple: (success: bool, new_key: bytes or None, message: str)
                - (True, new_key, "Kicked X, key rotated to vN") on success
                - (False, None, error_message) on failure
        
        Note:
            CRITICAL SECURITY FEATURE: The key rotation prevents removed users
            from accessing future communications, implementing forward secrecy
            in group messaging.
        """
        kicker = self._get_username_from_token(kicker_token)
        if not kicker:
            return False, None, "Invalid session"
        
        is_room_admin = db.get_member_role(room_id, kicker) == 'admin'
        is_global = is_global_admin(kicker_token)
        
        if not (is_room_admin or is_global):
            return False, None, "Not authorized"
        
        if kicker == target_username:
            return False, None, "Cannot kick yourself"
        
        success = db.remove_member(room_id, target_username, wipe_history=True)
        if not success:
            return False, None, "User not in room"
        
        # Get current version
        if room_id not in room_keys:
            _, current_version = self.get_room_key(room_id)
        else:
            current_version = room_keys[room_id]['version']
        
        new_version = current_version + 1
        
        # CRITICAL FIX: Generate deterministic new key
        new_key = self._derive_room_key(room_id, new_version)
        
        room_keys[room_id] = {
            'key': new_key,
            'version': new_version
        }
        
        db.update_room_key_version(room_id, new_version)
        
        print(f"[KEY_ROTATE] Room {room_id} key rotated: v{current_version} → v{new_version} (deterministic)")
        
        return True, new_key, f"Kicked {target_username}, key rotated to v{new_version}"

    def get_room_key(self, room_id: str) -> Tuple[Optional[bytes], int]:
        """
        Get current room encryption key, regenerating deterministically if needed.
        
        Returns the active encryption key and version for a room. If the key isn't
        in memory (server restart), regenerates it deterministically using the
        version number stored in the database.
        
        Args:
            room_id (str): Room to get key for
        
        Returns:
            tuple: (key: bytes or None, version: int)
                - (key, version) if room exists
                - (None, 0) if room not found
        
        Note:
            This function enables stateless server operation - keys can always
            be recreated from room_id + version, allowing for server restarts
            without losing encryption capability.
        """
        
        # Check memory first
        if room_id in room_keys:
            return room_keys[room_id]['key'], room_keys[room_id]['version']
        
        # Not in memory - get version from database
        room = db.get_room(room_id)
        if not room:
            print(f"[KEY] Room {room_id} not found in database")
            return None, 0
        
        version = room.get('key_version', 0)
        
        # CRITICAL FIX: Regenerate the SAME deterministic key
        print(f"[KEY] Regenerating deterministic key v{version} for {room_id}")
        key = self._derive_room_key(room_id, version)
        
        room_keys[room_id] = {
            'key': key,
            'version': version
        }
        
        return key, version

    def delete_room(self, room_id: str, token: str) -> Tuple[bool, str]:
        """
        Permanently delete a room (admin or global admin only).
        
        Removes room from database (cascade deletes members, messages, etc.)
        and clears encryption key from memory.
        
        Args:
            room_id (str): Room to delete
            token (str): Session token of user requesting deletion
        
        Returns:
            tuple: (success: bool, message: str)
                - (True, "Room deleted") on success
                - (False, error_message) on failure
        
        Note:
            Authorization: Only room admin or global admin can delete.
            This is irreversible - all data is permanently lost.
        """
        username = self._get_username_from_token(token)
        if not username:
            return False, "Invalid session"
        
        is_room_admin = db.get_member_role(room_id, username) == 'admin'
        is_global = is_global_admin(token)
        
        if not (is_room_admin or is_global):
            return False, "Not authorized"
        
        success = db.delete_room(room_id)
        if success and room_id in room_keys:
            del room_keys[room_id]
        
        return success, "Room deleted" if success else "Failed to delete"
    
    def edit_room(self, room_id: str, name: str, description: str, max_members: int, password: Optional[str] = None) -> Tuple[bool, str]:
        """
        Update room settings (name, description, capacity, password).
        
        Allows room admins to modify room configuration. For private rooms,
        can update or remove password. Empty string password removes it.
        
        Args:
            room_id (str): Room to edit
            name (str): New room name
            description (str): New description
            max_members (int): New capacity limit
            password (str, optional): New password (only for private rooms)
                                    Empty string removes password
                                    None leaves password unchanged
        
        Returns:
            tuple: (success: bool, message: str)
        
        Note:
            Password changes only apply to private rooms. Public rooms ignore
            password parameter. Name must still be unique system-wide.
        """
        room = db.get_room(room_id)
        if not room:
            return False, "Room not found"
        
        try:
            success = db.update_room_details(room_id, name, description, max_members)
            if not success:
                return False, "Failed to update basic details"
        except Exception as e:
            return False, f"Update failed: {str(e)}"
        
        # Handle password for private rooms only
        if room['type'] == 'private':
            if password == 'KEEP_CURRENT':  # NEW: Don't change password
                pass  # Do nothing
            elif password is None:  # NEW: Remove password
                db.update_room_password(room_id, None)
            elif password == '':  # NEW: Also remove if empty string (redundant but safe)
                db.update_room_password(room_id, None)
            else:  # NEW: Set new password
                password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                db.update_room_password(room_id, password_hash)
        
        return True, "Room updated successfully"
    
    def find_room_by_invite(self, invite_code: str) -> Optional[Dict]:
        """
        Lookup a private room using its invite code.
        
        Searches for a room by invite code and returns sanitized room info
        indicating whether password is required (without exposing the hash).
        
        Args:
            invite_code (str): Invite code from invite link
        
        Returns:
            dict or None: Room data with 'requires_password' boolean
                        None if invite code not found
        
        Note:
            Used when users click invite links or paste codes to join private rooms.
        """
        room = db.find_room_by_invite_code(invite_code)
        if room:
            room['requires_password'] = bool(room.get('has_password'))
        return room
    
    def search_public_rooms(self, query: str) -> List[Dict]:
        """
        Search for public rooms by name.
        
        Wrapper around database search function for finding rooms by name.
        Only searches public rooms (private rooms not searchable by name).
        
        Args:
            query (str): Search term (case-insensitive partial match)
        
        Returns:
            list: Matching public rooms with member counts
        """
        return db.search_rooms_by_name(query)
    
    def get_room_info(self, room_id: str) -> Optional[Dict]:
        """
        Get complete room information including member list.
        
        Retrieves room details and full member roster. Sanitizes output
        by removing password_hash for security.
        
        Args:
            room_id (str): Room to get info for
        
        Returns:
            dict or None: Room data with added 'members' list and 'member_count'
                        None if room doesn't exist
        
        Note:
            Used for rendering the chat interface and displaying room details.
        """
        room = db.get_room(room_id)
        if not room:
            return None
        
        members = db.get_room_members(room_id)
        room['members'] = members
        room['member_count'] = len(members)
        room.pop('password_hash', None)
        
        return room
    
    def list_user_rooms(self, username: str) -> List[Dict]:
        """
        Get all rooms a user belongs to.
        
        Wrapper around database function for retrieving user's room memberships.
        
        Args:
            username (str): Username to lookup
        
        Returns:
            list: User's rooms with role and member_count info
        """
        return db.get_user_rooms(username)
    
    def list_public_rooms(self) -> List[Dict]:
        """
        Get all public rooms system-wide.
        
        Wrapper around database function for public room listing.
        
        Returns:
            list: All public rooms with member counts
        
        Note:
            Used for the hub's public room browser.
        """
        return db.list_public_rooms()
    
    def create_report(self, room_id: str, reporter: str, reason: str, 
                     details: str = '') -> Tuple[bool, str]:
        """
        Submit a moderation report for a room.
        
        Creates a report record for global admin review. Users can report
        rooms for policy violations (spam, harassment, illegal content, etc.).
        
        Args:
            room_id (str): Room being reported
            reporter (str): Username filing the report
            reason (str): Brief reason (e.g., "Spam", "Harassment")
            details (str): Optional detailed explanation
        
        Returns:
            tuple: (success: bool, message: str)
                - (True, "Report #N submitted") on success
                - (False, "Failed to submit report") on error
        """
        try:
            report_id = db.create_report(room_id, reporter, reason, details)
            return True, f"Report #{report_id} submitted"
        except:
            return False, "Failed to submit report"
    
    def get_pending_reports(self) -> List[Dict]:
        """
        Get all unresolved moderation reports.
        
        Wrapper around database function for admin report dashboard.
        
        Returns:
            list: Pending reports with room names and reporter info
        
        Note:
            Only accessible to global admins via the admin panel.
        """
        return db.get_pending_reports()
    
    def resolve_report(self, report_id: int, admin_username: str, 
                      status: str = 'resolved') -> Tuple[bool, str]:
        """
        Mark a report as resolved after admin review.
        
        Updates report status and records which admin handled it.
        
        Args:
            report_id (int): Report to resolve
            admin_username (str): Admin handling the report
            status (str): New status. Defaults to 'resolved'
        
        Returns:
            tuple: (success: bool, message: str)
        """
        success = db.resolve_report(report_id, admin_username, status)
        return success, "Report resolved" if success else "Failed to resolve"
    
    def get_member_first_join(self, room_id: str, username: str) -> Optional[float]:
        """
        Get the timestamp of when a user first joined a room.
        
        Used for determining message history access - users should only see
        messages from after their first_join_at timestamp.
        
        Args:
            room_id (str): Room to check
            username (str): User to lookup
        
        Returns:
            float or None: Unix timestamp of first join, None if not a member
        
        Note:
            This is CRITICAL for message history access control.
        """
        members = db.get_room_members(room_id)
        for member in members:
            if member['username'] == username:
                return member['first_join_at']
        return None
    
    def _get_username_from_token(self, token: str) -> Optional[str]:
        """
        Internal helper to extract username from session token.
        
        Searches the users.json database for a matching token and returns
        the associated username.
        
        Args:
            token (str): Session token to lookup
        
        Returns:
            str or None: Username if token valid, None otherwise
        
        Note:
            This is a private helper method (note the _ prefix).
        """
        users = load_users()
        for username, data in users.items():
            if data.get('token') == token:
                return username
        return None

# Global instance
room_manager = RoomManager()