import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import bcrypt

USERS_FILE = 'users.json'

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    # Pre-set admin on first run
    admin_pass = bcrypt.hashpw(b'adminpass', bcrypt.gensalt()).decode()
    users = {'admin': {'password': admin_pass, 'role': 'admin', 'token': None}}
    save_users(users)
    return users

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

def register(username, password):
    users = load_users()
    if username in users:
        return False, "User exists"
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[username] = {'password': hashed, 'role': 'user', 'token': None}
    save_users(users)
    return True, "Registered"

def login(username, password):
    users = load_users()
    if username not in users:
        return False, None, "No user"
    if bcrypt.checkpw(password.encode(), users[username]['password'].encode()):
        token = f"{username}_token_{os.urandom(8).hex()}"
        users[username]['token'] = token
        save_users(users)
        return True, token, users[username]['role']
    return False, None, "Wrong pass"

def is_admin(token):
    users = load_users()
    for u, data in users.items():
        if data.get('token') == token:
            return data['role'] == 'admin'
    return False

def logout(token):
    users = load_users()
    for u, data in users.items():
        if data['token'] == token:
            data['token'] = None
            save_users(users)
            return True
    return False