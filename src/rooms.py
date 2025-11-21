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
    def __init__(self):
        """Initialize room manager and load existing room keys"""
        pass
    
    def create_room(self, name: str, creator: str, room_type: str = 'public',
                   password: Optional[str] = None, description: str = '',
                   max_members: int = 50) -> Tuple[bool, Optional[str], str]:
        """
        Create a new room with SIMPLIFIED access control:
        - Public rooms: no password, no invite code
        - Private rooms: ALWAYS have invite code, OPTIONAL password
        """
        if not name or len(name) > 50:
            return False, None, "Invalid room name"
        
        room_id = generate_room_id(name)
        
        # Access control for private rooms
        password_hash = None
        invite_code = None
        
        if room_type == 'private':
            # ALWAYS generate invite code for private rooms
            invite_code = generate_invite_code()
            
            # Optional password protection
            if password:
                password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        
        # Create room in database
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
        
        # Generate initial encryption key
        room_keys[room_id] = {
            'key': os.urandom(32),
            'version': 0
        }
        
        return True, room_id, f"Room '{name}' created"
    
    def join_room(self, room_id: str, username: str, password: Optional[str] = None,
                 invite_code: Optional[str] = None) -> Tuple[bool, Optional[bytes], str]:
        """
        Join a room with SIMPLIFIED access control:
        - Public: anyone can join
        - Private: need invite code, may need password
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
        
        # Add or re-add user to room (preserving role if rejoining)
        if current_role:
            success = db.add_member(room_id, username, current_role)
        else:
            success = db.add_member(room_id, username, 'member')
        
        if not success:
            return False, None, "Failed to join room"
        
        # Ensure room key exists
        if room_id not in room_keys:
            room_keys[room_id] = {
                'key': os.urandom(32),
                'version': room.get('key_version', 0)
            }
        
        return True, room_keys[room_id]['key'], f"Joined '{room['name']}'"
    
    def leave_room(self, room_id: str, username: str) -> Tuple[bool, Optional[str], str]:
        """
        Leave a room
        Returns: (success, new_admin, message)
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
        
        # Remove member (keep first_join_at for history)
        db.remove_member(room_id, username, wipe_history=False)
        
        return True, new_admin, "Left room"
    
    def kick_user(self, room_id: str, kicker_token: str, target_username: str) -> Tuple[bool, Optional[bytes], str]:
        """
        Kick user from room and rotate key
        Returns: (success, new_key, message)
        """
        kicker = self._get_username_from_token(kicker_token)
        if not kicker:
            return False, None, "Invalid session"
        
        # Check if kicker is room admin or global admin
        is_room_admin = db.get_member_role(room_id, kicker) == 'admin'
        is_global = is_global_admin(kicker_token)
        
        if not (is_room_admin or is_global):
            return False, None, "Not authorized"
        
        if kicker == target_username:
            return False, None, "Cannot kick yourself"
        
        # Remove member completely (wipe history access)
        success = db.remove_member(room_id, target_username, wipe_history=True)
        if not success:
            return False, None, "User not in room"
        
        # Rotate room key
        if room_id not in room_keys:
            room_keys[room_id] = {'key': os.urandom(32), 'version': 0}
        
        old_key = room_keys[room_id]['key']
        new_version = room_keys[room_id]['version'] + 1
        new_key = crypto.ratchet_key(old_key, version=new_version)
        
        room_keys[room_id] = {
            'key': new_key,
            'version': new_version
        }
        
        db.update_room_key_version(room_id, new_version)
        
        return True, new_key, f"Kicked {target_username}, key rotated to v{new_version}"
    
    def get_room_key(self, room_id: str) -> Tuple[Optional[bytes], int]:
        """Get current room key and version"""
        if room_id not in room_keys:
            room = db.get_room(room_id)
            if room:
                room_keys[room_id] = {
                    'key': os.urandom(32),
                    'version': room.get('key_version', 0)
                }
        
        if room_id in room_keys:
            return room_keys[room_id]['key'], room_keys[room_id]['version']
        return None, 0
    
    def delete_room(self, room_id: str, token: str) -> Tuple[bool, str]:
        """Delete a room (room admin or global admin)"""
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
        """Edit room details - password can be added, removed, or changed"""
        room = db.get_room(room_id)
        if not room:
            return False, "Room not found"
        
        # Update name, description, max_members
        try:
            success = db.update_room_details(room_id, name, description, max_members)
            if not success:
                return False, "Failed to update basic details"
        except Exception as e:
            return False, f"Update failed: {str(e)}"
        
        # Handle password for private rooms only
        if room['type'] == 'private':
            if password is not None:
                if password == '':
                    # Remove password (set to NULL)
                    db.update_room_password(room_id, None)
                else:
                    # Set or update password
                    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                    db.update_room_password(room_id, password_hash)
        
        return True, "Room updated successfully"
    
    def find_room_by_invite(self, invite_code: str) -> Optional[Dict]:
        """Find a private room by invite code"""
        room = db.find_room_by_invite_code(invite_code)
        if room:
            # Indicate if password is required
            room['requires_password'] = bool(room.get('has_password'))
        return room
    
    def search_public_rooms(self, query: str) -> List[Dict]:
        """Search public rooms by name"""
        return db.search_rooms_by_name(query)
    
    def get_room_info(self, room_id: str) -> Optional[Dict]:
        """Get room information with member list"""
        room = db.get_room(room_id)
        if not room:
            return None
        
        members = db.get_room_members(room_id)
        room['members'] = members
        room['member_count'] = len(members)
        
        # Don't expose sensitive data
        room.pop('password_hash', None)
        
        return room
    
    def list_user_rooms(self, username: str) -> List[Dict]:
        """Get all rooms user is in"""
        return db.get_user_rooms(username)
    
    def list_public_rooms(self) -> List[Dict]:
        """Get all public rooms"""
        return db.list_public_rooms()
    
    def create_report(self, room_id: str, reporter: str, reason: str, 
                     details: str = '') -> Tuple[bool, str]:
        """Create a report for a room"""
        try:
            report_id = db.create_report(room_id, reporter, reason, details)
            return True, f"Report #{report_id} submitted"
        except:
            return False, "Failed to submit report"
    
    def get_pending_reports(self) -> List[Dict]:
        """Get all pending reports (global admin only)"""
        return db.get_pending_reports()
    
    def resolve_report(self, report_id: int, admin_username: str, 
                      status: str = 'resolved') -> Tuple[bool, str]:
        """Resolve a report"""
        success = db.resolve_report(report_id, admin_username, status)
        return success, "Report resolved" if success else "Failed to resolve"
    
    def _get_username_from_token(self, token: str) -> Optional[str]:
        """Helper to get username from token"""
        users = load_users()
        for username, data in users.items():
            if data.get('token') == token:
                return username
        return None

# Global instance
room_manager = RoomManager()