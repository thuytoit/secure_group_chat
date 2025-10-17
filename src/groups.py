import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
from users import load_users, save_users
import crypto

GROUPS_FILE = 'groups.json'

class GroupManager:
    def __init__(self):
        if os.path.exists(GROUPS_FILE):
            with open(GROUPS_FILE, 'r') as f:
                data = json.load(f)
            # Decode hex keys back to bytes
            for group_name, group in data.items():
                if 'key' in group and isinstance(group['key'], str):
                    group['key'] = bytes.fromhex(group['key'])
                # Ensure version tracking exists
                if 'version' not in group:
                    group['version'] = 0
            self.groups = data
        else:
            self.groups = {
                'main_group': {
                    'members': [], 
                    'key': os.urandom(32),
                    'version': 0  # Track key rotation version
                }
            }
            self.save_groups()

    def save_groups(self):
        """Save groups to JSON, encoding bytes to hex"""
        data = {}
        for group_name, group in self.groups.items():
            new_group = group.copy()
            if 'key' in group and isinstance(group['key'], bytes):
                new_group['key'] = group['key'].hex()
            data[group_name] = new_group
        with open(GROUPS_FILE, 'w') as f:
            json.dump(data, f, indent=2)

    def add_user(self, username, token):
        """Add user to group (they get current key)"""
        group = self.groups['main_group']
        if username not in group['members']:
            group['members'].append(username)
            if 'key' not in group or group['key'] is None:
                group['key'] = os.urandom(32)
            if 'version' not in group:
                group['version'] = 0
            self.save_groups()
            return True, group['key'], "Added"
        return False, None, "Already in"

    def kick_user(self, username, token):
        """Kick user and rotate group key"""
        from users import is_admin
        if not is_admin(token):
            return False, None, "Not admin"
        
        group = self.groups['main_group']
        
        if username not in group['members']:
            return False, None, "Not found"
        
        # Remove the user
        group['members'].remove(username)
        
        # Invalidate token
        users = load_users()
        if username in users:
            users[username]['token'] = None
            save_users(users)
        
        # Increment version and ratchet key
        if 'version' not in group:
            group['version'] = 0
        
        group['version'] += 1
        old_key = group['key']
        
        # Deterministically derive new key from old key + version
        new_key = crypto.ratchet_key(old_key, version=group['version'])
        group['key'] = new_key
        
        print(f"[GROUPS] Kicked {username}, rotated from v{group['version']-1} to v{group['version']}")
        print(f"[GROUPS] Old key: {old_key.hex()[:20]}...")
        print(f"[GROUPS] New key: {new_key.hex()[:20]}...")
        
        self.save_groups()
        return True, new_key, f"Kicked + rotated (v{group['version']})"

    def get_group_key(self, group_name='main_group'):
        """Get current group key and version"""
        group = self.groups.get(group_name, {})
        return group.get('key'), group.get('version', 0)