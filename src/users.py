import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import bcrypt
import os

from pathlib import Path
USERS_FILE = Path(__file__).parent.parent / 'users.json'

def load_users():
    """
    Load user database from JSON file or create default admin account.
    
    Reads the users.json file containing all registered users and their
    credentials. If the file doesn't exist, creates a new database with
    a default admin account (username: 'admin', password: 'adminpass').
    
    Returns:
        dict: User database mapping usernames to user data
              Format: {username: {'password': hashed_pw, 'role': role, 'token': session_token}}
    
    Note:
        The default admin account should be changed immediately in production.
        All passwords are stored as bcrypt hashes for security.
    """
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    # Pre-set admin on first run
    admin_pass = bcrypt.hashpw(b'adminpass', bcrypt.gensalt()).decode()
    users = {'admin': {'password': admin_pass, 'role': 'admin', 'token': None}}
    save_users(users)
    return users

def save_users(users):
    """
    Save user database to JSON file.
    
    Writes the complete user database to users.json, persisting all
    user accounts, password hashes, roles, and session tokens.
    
    Args:
        users (dict): Complete user database to save
    
    Note:
        This function performs a full overwrite of the users.json file.
    """
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

def register(username, password):
    """
    Register a new user account with bcrypt password hashing.
    
    Creates a new user account if the username is available. Passwords
    are hashed using bcrypt with automatic salt generation for security.
    New users are assigned the 'user' role by default.
    
    Args:
        username (str): Desired username (must be unique)
        password (str): Plain-text password (will be hashed)
    
    Returns:
        tuple: (success: bool, message: str)
               - (True, "Registered") if successful
               - (False, "User exists") if username is taken
    
    Example:
        >>> success, msg = register("alice", "password123")
        >>> print(success, msg)
        True Registered
    """
    users = load_users()
    if username in users:
        return False, "User exists"
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[username] = {'password': hashed, 'role': 'user', 'token': None}
    save_users(users)
    return True, "Registered"

def login(username, password):
    """
    Authenticate user and create/retrieve session token.
    
    Verifies username and password, then generates or retrieves an existing
    session token for maintaining user sessions across requests.
    
    Args:
        username (str): Username to authenticate
        password (str): Plain-text password to verify
    
    Returns:
        tuple: (success: bool, token: str or None, role: str or None)
               - (True, token, role) if authentication successful
               - (False, None, "No user") if username not found
               - (False, None, "Wrong pass") if password incorrect
    
    Note:
        Tokens are generated once per user and persist until logout.
        Uses bcrypt for secure password comparison.
    """
    users = load_users()
    if username not in users:
        return False, None, "No user"
    if bcrypt.checkpw(password.encode(), users[username]['password'].encode()):
        if users[username].get('token') is None:
            token = f"{username}_token_{os.urandom(8).hex()}"
            users[username]['token'] = token
        else:
            token = users[username]['token']
        save_users(users)
        return True, token, users[username]['role']
    return False, None, "Wrong pass"

def is_admin(token):
    """
    Check if a session token belongs to a global admin user.
    
    Validates whether the provided session token corresponds to a user
    with 'admin' role, used for authorization checks throughout the app.
    
    Args:
        token (str): Session token to verify
    
    Returns:
        bool: True if token belongs to an admin user, False otherwise
    
    Note:
        Global admins have elevated privileges including the ability to
        delete any room and view all moderation reports.
    """
    users = load_users()
    for u, data in users.items():
        if data.get('token') == token:
            return data['role'] == 'admin'
    return False

def logout(token):
    """
    Invalidate a user's session by clearing their token.
    
    Removes the session token from the user's account, effectively
    logging them out and requiring re-authentication for future requests.
    
    Args:
        token (str): Session token to invalidate
    
    Returns:
        bool: True if logout successful, False if token not found
    """
    users = load_users()
    for u, data in users.items():
        if data['token'] == token:
            data['token'] = None
            save_users(users)
            return True
    return False

def get_username_from_token(token: str):
    """
    Get username from session token.
    
    Args:
        token (str): Session token to lookup
    
    Returns:
        str or None: Username if token valid, None otherwise
    """
    users = load_users()
    for username, data in users.items():
        if data.get('token') == token:
            return username
    return None

def delete_user_account(username):
    """
    Permanently delete a user account.
    
    This is for GDPR "Right to be Forgotten" compliance.
    Removes user from users.json permanently.
    
    Args:
        username (str): Username to delete
    
    Returns:
        bool: True if deleted, False if user doesn't exist or is admin
    """
    users = load_users()
    
    # Check if user exists
    if username not in users:
        return False
    
    # Prevent deleting admin (safety check)
    if users[username].get('role') == 'admin':
        return False
    
    # Delete the user
    del users[username]
    save_users(users)
    return True