import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
from users import is_admin

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
            self.groups = data
        else:
            self.groups = {'main_group': {'members': [], 'key': os.urandom(32)}}  # Initial bytes key
            self.save_groups()
        self.admin_token = 'admin123'  # From config

    def save_groups(self):
        # Encode bytes keys to hex for JSON
        data = {}
        for group_name, group in self.groups.items():
            new_group = group.copy()
            if 'key' in group and isinstance(group['key'], bytes):
                new_group['key'] = group['key'].hex()
            data[group_name] = new_group
        with open(GROUPS_FILE, 'w') as f:
            json.dump(data, f)

    def add_user(self, username, token):
        if not is_admin(token) and token != self.admin_token:
            return False, None, "Not authorized"
        group = self.groups['main_group']
        if username not in group['members']:
            group['members'].append(username)
            if 'key' not in group or group['key'] is None:
                group['key'] = os.urandom(32)  # Initial bytes key
            self.save_groups()
            return True, group['key'], "Added"
        return False, None, "Already in"

    def kick_user(self, username, token):
        if not is_admin(token) and token != self.admin_token:
            return False, None, "Not admin"
        group = self.groups['main_group']
        if username in group['members']:
            group['members'].remove(username)
            # Ratchet: New key (bytes)
            import src.crypto as crypto
            group['key'] = crypto.ratchet_key(group['key'])
            self.save_groups()
            return True, group['key'], "Kicked + rotated"
        return False, None, "Not found"