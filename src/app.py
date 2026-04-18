"""
Secure Multi-Room Chat Application - Main Server Module

This Flask application implements an end-to-end encrypted chat system with:
- User authentication and session management
- Multiple chat rooms (public and private)
- Real-time messaging via Socket.IO
- Diffie-Hellman key exchange for peer-to-peer key sharing (client-to-client)
- AES-256-CBC encryption for all message content
- Dynamic key rotation on user removal
- Multiple file attachments per message
- Message reactions and moderation
- Online presence indicators
- Typing indicators
- Report system with evidence attachments
- GDPR compliance (Right to Access and Right to Erasure)
- Live socket updates for real-time UI synchronization
- Automatic room ownership transfer on owner departure
- Dark mode support with user preferences

The server CANNOT decrypt message content (true E2EE) - it only facilitates
key exchange and routes encrypted data between clients.

Author: Thuy
Date: January 2026
"""
import sys
import os
import json
import logging
import datetime
import base64
import time
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from flask import send_from_directory

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, session, redirect, url_for, jsonify, send_file
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from users import register, login, is_admin as is_global_admin, logout, load_users, get_username_from_token
import bcrypt
from rooms import room_manager, room_keys
import database as db
from crypto import parameters
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
import io

import atexit

# Load config
CONFIG_PATH = Path(__file__).parent / 'config.json'
with open(CONFIG_PATH, 'r') as f:
    config = json.load(f)

app = Flask(__name__)
app.config['SECRET_KEY'] = config['secret_key']
app.config['DEBUG'] = config.get('flask_debug', False)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

UPLOAD_FOLDER = Path(__file__).parent / 'uploads'
UPLOAD_FOLDER.mkdir(exist_ok=True)
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'zip', 'mp4', 'mp3'}

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', max_http_buffer_size=22*1024*1024)

logging.basicConfig(level=logging.INFO if app.config['DEBUG'] else logging.WARNING)
logger = logging.getLogger(__name__)

connections = {}
active_sids = {}
room_sids = {}
backend = default_backend()

# Key management locks
key_locks = {}
connection_locks = threading.Lock()

def cleanup():
    """
    Cleanup function called on server shutdown.
    
    Ensures all database connections are properly closed before the
    application terminates, preventing data corruption or locked databases.
    
    Note:
        Registered with atexit to run automatically on shutdown.
    """
    logger.info("[SHUTDOWN] Closing database connections...")
    db.close_db()

def is_valid_user(token: str) -> bool:
    """
    Check if a session token is valid.
    
    Convenience wrapper around get_username_from_token for boolean checks.
    
    Args:
        token (str): Token to validate
    
    Returns:
        bool: True if token is valid, False otherwise
    """
    return get_username_from_token(token) is not None

def require_auth():
    """
    Decorator helper to enforce authentication on routes.
    
    Checks if user has valid session token. If not, redirects to login page.
    
    Returns:
        Response or None: Redirect response if unauthorized, None if authorized
    
    Example:
        @app.route('/protected')
        def protected():
            redirect_to = require_auth()
            if redirect_to:
                return redirect_to
            # ... authorized code ...
    """
    if 'token' not in session or not is_valid_user(session['token']):
        return redirect(url_for('index'))
    return None

def allowed_file(filename):
    """
    Check if a filename has an allowed extension for upload.
    
    Validates file uploads against whitelist of safe extensions to prevent
    malicious file uploads.
    
    Args:
        filename (str): Filename to check
    
    Returns:
        bool: True if extension is allowed, False otherwise
    
    Note:
        Allowed extensions defined in ALLOWED_EXTENSIONS constant.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def broadcast_room_update():
    """
    Notify all connected clients about room list changes.
    
    Broadcasts updated public room list to all users and sends personalized
    room lists to individual users. Called after room creation, deletion,
    or membership changes.
    
    Note:
        Uses Socket.IO emit to send real-time updates without page refresh.
    """
    public_rooms = room_manager.list_public_rooms()
    socketio.emit('room_list_update', {'public_rooms': public_rooms}, namespace='/')
    
    for sid, conn in list(connections.items()):
        if conn.get('username'):
            user_rooms = room_manager.list_user_rooms(conn['username'])
            socketio.emit('user_rooms_update', {'user_rooms': user_rooms}, room=sid)

def broadcast_member_update(room_id: str):
    """
    Send updated member list to all users in a room.
    
    Broadcasts current member roster to room, showing who's online and
    their roles. Called when users join, leave, or roles change.
    
    Args:
        room_id (str): Room to broadcast update to
    """
    members = db.get_room_members(room_id)
    socketio.emit('member_list_update', {
        'members': [{
            'username': m['username'],
            'role': m['role'],
            'joined_at': m['joined_at'],
            'is_online': m.get('is_online', 0),  # SEND ONLINE STATUS
            'last_seen': m.get('last_seen', 0)
        } for m in members]
    }, to=room_id)

def broadcast_reports_update():
    """
    Notify global admins about report queue changes.
    
    Broadcasts updated pending reports list to all connected clients
    (only admins will display this data). Called when reports are
    submitted or resolved.
    """
    try:
        pending_reports = room_manager.get_pending_reports()
        socketio.emit('reports_updated', {'pending_reports': pending_reports})
    except Exception as e:
        logger.error(f"Report broadcast error: {e}")

def get_room_lock(room_id: str):
    """
    Get or create a threading lock for a specific room.
    
    Returns a lock object for synchronizing concurrent operations on the
    same room (e.g., multiple users sending messages simultaneously).
    
    Args:
        room_id (str): Room to get lock for
    
    Returns:
        threading.Lock: Lock object for this room
    
    Note:
        Locks are created on-demand and stored in the global key_locks dict.
    """
    with connection_locks:
        if room_id not in key_locks:
            key_locks[room_id] = threading.Lock()
        return key_locks[room_id]
                            
def check_connection_health():
    """
    Background thread that monitors and cleans up stale connections.
    
    Runs every 30 seconds to find connections that have been stuck in
    "not ready" state for >30 seconds and removes them to prevent memory leaks.
    
    Note:
        Runs as a daemon thread, started automatically on server startup.
    """
    while True:
        try:
            current_time = time.time()
            stale_sids = []
            
            for sid, conn in list(connections.items()):
                # If connection has been in non-ready state for too long, clean it up
                if not conn.get('ready') and current_time - conn.get('connect_time', current_time) > 30:
                    stale_sids.append(sid)
                    logger.warning(f"[HEALTH] Removing stale connection {sid} for {conn.get('username')}")
            
            for sid in stale_sids:
                if sid in connections:
                    username = connections[sid].get('username')
                    room_id = connections[sid].get('room_id')
                    
                    # Clean up connection
                    if room_id:
                        leave_room(room_id, sid)
                        if room_id in room_sids and sid in room_sids[room_id]:
                            room_sids[room_id].remove(sid)
                    
                    if username in active_sids:
                        active_sids[username] = [s for s in active_sids[username] if s != sid]
                        if not active_sids[username]:
                            del active_sids[username]
                    
                    del connections[sid]
                    
                    logger.info(f"[HEALTH] Cleaned up stale connection for {username}")
        
        except Exception as e:
            logger.error(f"[HEALTH] Error in health check: {e}")
        
        time.sleep(30)

# Start health monitoring in background
health_thread = threading.Thread(target=check_connection_health, daemon=True)
health_thread.start()

# ===== HTTP ROUTES =====

@app.route('/')
def index():
    """
    Render the login/registration landing page.
    
    Returns:
        HTML: index.html template with login and registration forms
    """
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def do_register():
    """
    Handle user registration requests.
    
    Creates new user account with bcrypt password hashing.
    
    Form Data:
        username (str): Desired username (must be unique)
        password (str): Plain-text password (will be hashed)
    
    Returns:
        JSON: {'success': bool, 'msg': str}
    """
    username = request.form['username']
    password = request.form['password']
    success, msg = register(username, password)
    return jsonify({'success': success, 'msg': msg})

@app.route('/login', methods=['POST'])
def do_login():
    """
    Authenticate user and create session.
    
    Verifies credentials and generates session token stored in Flask session.
    
    Form Data:
        username (str): Username
        password (str): Password
    
    Returns:
        JSON: {'success': bool, 'token': str, 'role': str, 'msg': str}
    """
    username = request.form['username']
    password = request.form['password']
    success, token, role = login(username, password)
    if success:
        session['token'] = token
        session['username'] = username
        session['role'] = role
    return jsonify({'success': success, 'token': token, 'role': role, 
                   'msg': 'Logged in' if success else 'Invalid credentials'})

@app.route('/logout')
def do_logout():
    """
    Logout user and clear session.
    
    Invalidates session token and redirects to landing page.
    
    Returns:
        Redirect: To index page
    """
    token = session.get('token')
    if token:
        logout(token)
    session.clear()
    return redirect(url_for('index'))

@app.route('/hub')
def hub():
    """
    Render the main room selection hub.
    
    Shows user's rooms, public rooms, and admin panel (if admin).
    Requires authentication - redirects to login if not logged in.
    
    Returns:
        HTML: hub.html template with room listings and user info
    """
    redirect_to = require_auth()
    if redirect_to:
        return redirect_to
    
    user_rooms = room_manager.list_user_rooms(session['username'])
    public_rooms = room_manager.list_public_rooms()
    
    pending_reports = []
    if is_global_admin(session['token']):
        pending_reports = room_manager.get_pending_reports()
        # Parse evidence files JSON for display
        for report in pending_reports:
            if report.get('evidence_file'):
                try:
                    # Try to parse as JSON array
                    evidence_files = json.loads(report['evidence_file'])
                    if isinstance(evidence_files, list):
                        report['evidence_files'] = evidence_files
                    else:
                        report['evidence_files'] = [report['evidence_file']]
                except:
                    # Old format - single file
                    report['evidence_files'] = [report['evidence_file']]
            else:
                report['evidence_files'] = []
    
    return render_template('hub.html',
                         username=session['username'],
                         role=session['role'],
                         user_rooms=user_rooms,
                         public_rooms=public_rooms,
                         pending_reports=pending_reports,
                         is_global_admin=is_global_admin(session['token']))

@app.route('/chat/<room_id>')
def chat(room_id):
    """
    Render the chat interface for a specific room.
    
    Verifies user is a member of the room and loads room settings.
    Requires authentication.
    
    Args:
        room_id (str): Room to enter
    
    Returns:
        HTML: chat.html template with room data and crypto parameters
        Redirect: To hub if not a member or room doesn't exist
    """
    redirect_to = require_auth()
    if redirect_to:
        return redirect_to
    
    role = db.get_member_role(room_id, session['username'])
    if not role:
        return redirect(url_for('hub'))
    
    room_info = room_manager.get_room_info(room_id)
    if not room_info:
        return redirect(url_for('hub'))

    # Properly escape room name for JavaScript
    import json
    room_name_safe = json.dumps(room_info['name'])  # Escapes apostrophes!
    
    return render_template('chat.html',
                         username=session['username'],
                         role=session['role'],
                         room_id=room_id,
                         room_name=room_info['name'],  # For HTML title (safe)
                         room_name_js=room_name_safe,   # For JavaScript (safe)
                         room_description=room_info.get('description', ''),
                         room_max_members=room_info.get('max_members', 50),
                         room_role=role,
                         room_type=room_info['type'],
                         invite_code=room_info.get('invite_code', ''),
                         token=session['token'],
                         salt=config['salt'],
                         iterations=config['iterations'],
                         is_global_admin=is_global_admin(session['token']),
                         now=datetime.datetime.now(datetime.timezone.utc).isoformat())

@app.route('/api/rooms/create', methods=['POST'])
def create_room_api():
    """
    API endpoint to create a new room.
    
    JSON Body:
        name (str): Room name (required, max 50 chars)
        type (str): 'public' or 'private' (default: 'public')
        password (str, optional): Password for private rooms
        description (str): Room description
        max_members (int): Capacity (default: 50)
    
    Returns:
        JSON: {'success': bool, 'room_id': str, 'msg': str}
    
    Note:
        Creates room, adds creator as admin, generates encryption key.
    """
    if 'token' not in session or not is_valid_user(session['token']):
        return jsonify({'success': False, 'msg': 'Unauthorized'}), 401
    
    try:
        data = request.json
        name = data.get('name', '').strip()
        room_type = data.get('type', 'public')
        password = data.get('password', '').strip() if data.get('password') else None
        description = data.get('description', '')
        max_members = data.get('max_members', 50)
        
        if not name:
            return jsonify({'success': False, 'msg': 'Room name required'})
        
        if password == '':
            password = None
        
        success, room_id, msg = room_manager.create_room(
            name=name,
            creator=session['username'],
            room_type=room_type,
            password=password,
            description=description,
            max_members=max_members
        )
        
        if success:
            broadcast_room_update()
        
        return jsonify({'success': success, 'room_id': room_id, 'msg': msg})
    except Exception as e:
        logger.error(f"Create room error: {e}")
        return jsonify({'success': False, 'msg': str(e)}), 500

@app.route('/api/rooms/join', methods=['POST'])
def join_room_api():
    """
    API endpoint to join an existing room.
    
    JSON Body:
        room_id (str, optional): Room to join
        password (str, optional): Password (if required)
        invite_code (str, optional): Invite code for private rooms
    
    Returns:
        JSON: {'success': bool, 'room_id': str, 'msg': str}
    
    Note:
        Can join by room_id (public rooms) or invite_code (private rooms).
    """
    if 'token' not in session or not is_valid_user(session['token']):
        return jsonify({'success': False, 'msg': 'Unauthorized'}), 401
    
    data = request.json
    room_id = data.get('room_id')
    password = data.get('password')
    invite_code = data.get('invite_code')
    
    # If room_id is not provided but invite_code is, find room by invite
    if not room_id and invite_code:
        room = room_manager.find_room_by_invite(invite_code)
        if room:
            room_id = room['id']
        else:
            return jsonify({'success': False, 'msg': 'Invalid invite code'})
    
    success, room_id, msg = room_manager.join_room(
        room_id=room_id,
        username=session['username'],
        password=password,
        invite_code=invite_code
    )
    
    if success:
        broadcast_room_update()
        return jsonify({'success': True, 'room_id': room_id, 'msg': msg})
    else:
        return jsonify({'success': False, 'msg': msg})

@app.route('/api/rooms/<room_id>/edit', methods=['POST'])
def edit_room_api(room_id):
    """
    API endpoint to edit room settings (admin only).
    
    JSON Body:
        name (str): New room name
        description (str): New description
        max_members (int): New capacity
        password (str, optional): New password (private rooms only)
    
    Returns:
        JSON: {'success': bool, 'msg': str}
    
    Authorization:
        Room admin or global admin only
    """
    if 'token' not in session or not is_valid_user(session['token']):
        return jsonify({'success': False, 'msg': 'Unauthorized'}), 401
    
    role = db.get_member_role(room_id, session['username'])
    if role != 'admin' and not is_global_admin(session['token']):
        return jsonify({'success': False, 'msg': 'Not authorized'}), 403
    
    try:
        data = request.json
        name = data.get('name', '').strip()
        description = data.get('description', '').strip()
        max_members = int(data.get('max_members', 50))
        password_raw = data.get('password')
        if password_raw is not None:  # Field was sent
            password = password_raw.strip()
            if password == '':  # Empty string means remove password
                password = None
        else:  # Field not sent means don't change password
            password = 'KEEP_CURRENT'  # Special value
        
        if not name:
            return jsonify({'success': False, 'msg': 'Room name required'})
        
        if password == '':
            password = None
        
        success, msg = room_manager.edit_room(room_id, name, description, max_members, password)
        
        if success:
            # Broadcast to hub
            broadcast_room_update()
            
            # CRITICAL FIX: Don't force refresh - just update the UI
            socketio.emit('room_updated', {
                'room_id': room_id,
                'name': name,
                'description': description,
                'max_members': max_members,
                'refresh': False  # Changed from True to False
            }, room=room_id)
            
            socketio.emit('room_info_updated', {
                'room_id': room_id,
                'name': name,
                'description': description,
                'max_members': max_members
            }, room='hub')
        
        return jsonify({'success': success, 'msg': msg})
    except Exception as e:
        logger.error(f"Edit room error: {e}")
        return jsonify({'success': False, 'msg': str(e)}), 500

@app.route('/api/rooms/<room_id>/switch-type', methods=['POST'])
def switch_room_type_api(room_id):
    """
    API endpoint to switch room between public and private modes.
    
    JSON Body:
        new_type (str): 'public' or 'private'
        password (str, optional): Password when switching to private
    
    Returns:
        JSON: {'success': bool, 'invite_code': str (optional), 'msg': str}
    
    Authorization:
        Room admin or global admin only
    
    Note:
        Switching to private generates a new invite code for security.
        Switching to public removes all access control.
    """
    if 'token' not in session or not is_valid_user(session['token']):
        return jsonify({'success': False, 'msg': 'Unauthorized'}), 401
    
    role = db.get_member_role(room_id, session['username'])
    if role != 'admin' and not is_global_admin(session['token']):
        return jsonify({'success': False, 'msg': 'Not authorized'}), 403
    
    try:
        data = request.json
        new_type = data.get('new_type', '').strip().lower()
        password = data.get('password', '').strip() if data.get('password') else None
        
        if new_type not in ['public', 'private']:
            return jsonify({'success': False, 'msg': 'Invalid room type'}), 400
        
        success, invite_code, msg = room_manager.switch_room_type(
            room_id, 
            session['token'], 
            new_type, 
            password
        )
        
        if success:
            # Broadcast room update to all clients
            broadcast_room_update()
            
            # Notify users in the room
            socketio.emit('room_type_changed', {
                'room_id': room_id,
                'new_type': new_type,
                'invite_code': invite_code,
                'msg': msg
            }, room=room_id)
            
            response = {'success': True, 'msg': msg}
            if invite_code:
                response['invite_code'] = invite_code
            
            return jsonify(response)
        else:
            return jsonify({'success': False, 'msg': msg}), 400
            
    except Exception as e:
        logger.error(f"Switch room type error: {e}")
        return jsonify({'success': False, 'msg': str(e)}), 500

@app.route('/api/rooms/<room_id>/report', methods=['POST'])
def report_room(room_id):
    """
    API endpoint to report a room for moderation.
    
    JSON Body:
        reason (str): Brief reason (required)
        details (str): Detailed explanation (optional)
        evidence_data (str, optional): Base64-encoded screenshot/evidence
        evidence_filename (str, optional): Original filename of evidence
    
    Returns:
        JSON: {'success': bool, 'msg': str}
    
    Note:
        Creates report for global admin review with optional evidence attachment.
    """
    if 'token' not in session or not is_valid_user(session['token']):
        return jsonify({'success': False, 'msg': 'Unauthorized'}), 401
    
    try:
        data = request.json
        reason = data.get('reason', '').strip()
        details = data.get('details', '').strip()
        evidence_files_data = data.get('evidence_files', [])
        
        if not reason:
            return jsonify({'success': False, 'msg': 'Reason required'})
        
        # Handle multiple evidence files upload
        evidence_paths = []
        if evidence_files_data:
            try:
                # Create evidence folder if it doesn't exist
                evidence_folder = UPLOAD_FOLDER / 'evidence'
                evidence_folder.mkdir(exist_ok=True)
                
                for file_obj in evidence_files_data:
                    evidence_data = file_obj.get('data')
                    evidence_filename = file_obj.get('filename')
                    
                    if not evidence_data or not evidence_filename:
                        continue
                    
                    # Decode base64
                    file_data = base64.b64decode(evidence_data.split(',')[1] if ',' in evidence_data else evidence_data)
                    
                    # Validate size (max 5MB per file)
                    if len(file_data) > 5 * 1024 * 1024:
                        return jsonify({'success': False, 'msg': f'{evidence_filename} is too large (max 5MB)'}), 400
                    
                    # Generate unique filename
                    import secrets
                    file_ext = evidence_filename.rsplit('.', 1)[1] if '.' in evidence_filename else 'png'
                    evidence_id = f"evidence_{secrets.token_hex(16)}.{file_ext}"
                    evidence_path = evidence_folder / evidence_id
                    
                    # Save file
                    with open(evidence_path, 'wb') as f:
                        f.write(file_data)
                    
                    # Store relative path
                    evidence_paths.append(f"evidence/{evidence_id}")
                    logger.info(f"[EVIDENCE] Saved evidence for report: evidence/{evidence_id}")
                
            except Exception as e:
                logger.error(f"[EVIDENCE] Upload error: {e}")
                return jsonify({'success': False, 'msg': 'Failed to upload evidence'}), 500
        
        # Convert array to JSON string for storage
        evidence_json = json.dumps(evidence_paths) if evidence_paths else None
        success, msg = room_manager.create_report(room_id, session['username'], reason, details, evidence_json)
        
        if success:
            broadcast_reports_update()
        
        return jsonify({'success': success, 'msg': msg})
    except Exception as e:
        logger.error(f"Report error: {e}")
        return jsonify({'success': False, 'msg': str(e)}), 500

@app.route('/api/evidence/<path:filename>')
def serve_evidence(filename):
    """
    Serve evidence files for admin review (admin only).
    
    Args:
        filename (str): Evidence filename
    
    Returns:
        File: Evidence image/file
    
    Authorization:
        Global admin only
    """
    if 'token' not in session or not is_global_admin(session['token']):
        return jsonify({'success': False, 'msg': 'Unauthorized'}), 401
    
    evidence_folder = UPLOAD_FOLDER / 'evidence'
    return send_from_directory(evidence_folder, filename)

@app.route('/api/reports/<int:report_id>/resolve', methods=['POST'])
def resolve_report_api(report_id):
    """
    API endpoint to resolve a moderation report (admin only).
    
    JSON Body:
        status (str): New status (default: 'resolved')
    
    Returns:
        JSON: {'success': bool, 'msg': str}
    
    Authorization:
        Global admin only
    """
    if 'token' not in session or not is_global_admin(session['token']):
        return jsonify({'success': False, 'msg': 'Unauthorized'}), 401
    
    try:
        data = request.json
        status = data.get('status', 'resolved')
        
        success, msg = room_manager.resolve_report(report_id, session['username'], status)
        
        if success:
            broadcast_reports_update()
        
        return jsonify({'success': success, 'msg': msg})
    except Exception as e:
        logger.error(f"Resolve report error: {e}")
        return jsonify({'success': False, 'msg': str(e)}), 500

@app.route('/api/rooms/<room_id>/delete', methods=['POST'])
def delete_room_api(room_id):
    """
    API endpoint to permanently delete a room.
    
    Returns:
        JSON: {'success': bool, 'msg': str}
    
    Authorization:
        Room admin or global admin only
    
    Warning:
        Irreversible - all messages and data permanently deleted.
    """
    if 'token' not in session:
        return jsonify({'success': False, 'msg': 'Unauthorized'}), 401
    
    role = db.get_member_role(room_id, session['username'])
    if role != 'admin' and not is_global_admin(session['token']):
        return jsonify({'success': False, 'msg': 'Not authorized'}), 403
    
    success, msg = room_manager.delete_room(room_id, session['token'])
    
    if success:
        broadcast_room_update()
        socketio.emit('room_deleted', {'room_id': room_id}, room=room_id)
    
    return jsonify({'success': success, 'msg': msg})

@app.route('/api/rooms/search', methods=['GET'])
def search_rooms_api():
    """
    API endpoint to search for rooms.
    
    Query Parameters:
        q (str): Search query for room name (public rooms only)
        invite (str): Invite code to lookup (private rooms)
    
    Returns:
        JSON: {'success': bool, 'rooms': list, 'msg': str}
    
    Note:
        Searches by name (public) OR invite code (private), not both.
    """
    if 'token' not in session or not is_valid_user(session['token']):
        return jsonify({'success': False, 'msg': 'Unauthorized'}), 401
    
    query = request.args.get('q', '').strip().lower()
    invite_code = request.args.get('invite', '').strip()
    
    if invite_code:
        room = room_manager.find_room_by_invite(invite_code)
        if room:
            return jsonify({'success': True, 'rooms': [room]})
        return jsonify({'success': False, 'msg': 'Invalid invite code', 'rooms': []})
    
    rooms = room_manager.search_public_rooms(query)
    return jsonify({'success': True, 'rooms': rooms})

@app.route('/api/rooms/<room_id>/snapshot', methods=['GET'])
def get_room_snapshot_api(room_id):
    """
    API endpoint to get room snapshot for admin review (admin only).
    
    Returns comprehensive room overview including members, recent message
    metadata (encrypted content not exposed), and room statistics.
    
    Args:
        room_id (str): Room to get snapshot for
    
    Returns:
        JSON: {
            'success': bool,
            'snapshot': {
                'room_info': dict,
                'members': list,
                'recent_messages': list,
                'member_count': int,
                'message_count': int
            }
        }
    
    Authorization:
        Global admin only
    
    Note:
        Messages remain encrypted - admin sees metadata only.
        Preserves E2EE while enabling moderation oversight.
    """
    if 'token' not in session or not is_global_admin(session['token']):
        return jsonify({'success': False, 'msg': 'Unauthorized'}), 401
    
    try:
        snapshot = db.get_room_snapshot(room_id)
        
        if not snapshot:
            return jsonify({'success': False, 'msg': 'Room not found'}), 404
        
        # Add report history
        report_history = db.get_room_report_history(room_id)
        snapshot['report_history'] = report_history
        
        return jsonify({
            'success': True,
            'snapshot': snapshot
        })
    except Exception as e:
        logger.error(f"Snapshot error: {e}")
        return jsonify({'success': False, 'msg': str(e)}), 500

@app.route('/api/files/<file_id>')
def download_file(file_id):
    """
    Serve an uploaded file for download.
    
    For encrypted files, returns encrypted blob. Client must decrypt
    using the key_version stored in message metadata.
    """
    if 'token' not in session or not is_valid_user(session['token']):
        return jsonify({'success': False, 'msg': 'Unauthorized'}), 401
    
    # Find file in uploads folder
    import glob
    matching_files = glob.glob(str(UPLOAD_FOLDER / f"{file_id}_*"))
    
    if not matching_files:
        return jsonify({'success': False, 'msg': 'File not found'}), 404
    
    file_path = Path(matching_files[0])
    original_filename = file_path.name.split('_', 1)[1]  # Remove "file_xxxxx_" prefix
    
    # Return file as-is (encrypted or plain)
    # Client will decrypt if needed based on is_encrypted flag in metadata
    return send_file(
        file_path,
        download_name=original_filename,
        as_attachment=True
    )
    
@app.route('/api/account/delete', methods=['POST'])
def delete_account_api():
    """
    Delete user account permanently (GDPR Right to Erasure).
    
    Returns:
        JSON: {'success': bool, 'msg': str, 'stats': dict}
    """
    if 'token' not in session or not is_valid_user(session['token']):
        return jsonify({'success': False, 'msg': 'Unauthorized'}), 401
    
    try:
        data = request.json
        password = data.get('password', '')
        
        if not password:
            return jsonify({'success': False, 'msg': 'Password required'})
        
        username = session['username']
        
        # Verify password
        users = load_users()
        if username not in users:
            return jsonify({'success': False, 'msg': 'User not found'})
        
        if not bcrypt.checkpw(password.encode(), users[username]['password'].encode()):
            return jsonify({'success': False, 'msg': 'Incorrect password'})
        
        # Get user's room memberships BEFORE deletion (for notifications)
        user_rooms = db.get_user_room_ids(username)
        
        # Delete all data from database
        stats = db.delete_user_data_gdpr(username)
        
        # Delete user account
        from users import delete_user_account
        success = delete_user_account(username)
        
        if success:
            logger.info(f"[GDPR] Account deleted: {username}, Stats: {stats}")
            
            # LIVE UPDATE: Notify all rooms this user was in
            for room_id in user_rooms:
                # Skip rooms that were deleted (they're in stats['deleted_rooms'])
                if room_id in stats.get('deleted_rooms', []):
                    continue
                
                # Check if ownership was transferred
                members = db.get_room_members(room_id)
                admin_member = next((m for m in members if m['role'] == 'admin'), None)
                
                # Broadcast user deletion to room
                socketio.emit('user_deleted', {
                    'username': username,
                    'msg': f'{username} deleted their account'
                }, room=room_id)
                
                # If ownership transferred, notify room
                if admin_member and admin_member['username'] != username:
                    socketio.emit('sys_msg', {
                        'type': 'admin_transfer',
                        'user': admin_member['username'],
                        'msg': f"{admin_member['username']} is now the room admin"
                    }, room=room_id)
                
                # Update member list
                broadcast_member_update(room_id)
            
            # CRITICAL: Broadcast room updates to hub
            # This makes deleted rooms disappear from hub immediately
            broadcast_room_update()
            
            session.clear()
            return jsonify({
                'success': True,
                'msg': 'Account permanently deleted',
                'stats': stats
            })
        else:
            return jsonify({'success': False, 'msg': 'Failed to delete'})
            
    except Exception as e:
        logger.error(f"[GDPR] Delete error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'msg': str(e)}), 500
        
@app.route('/api/account/export', methods=['GET'])
def export_account_data():
    """
    Export all user data with ENCRYPTED messages (GDPR Right to Access).
    
    Returns encrypted messages because server cannot decrypt in TRUE E2EE.
    Client will decrypt using keys from localStorage before downloading.
    
    Returns:
        JSON: All user data including encrypted messages for client-side decryption
    """
    if 'token' not in session or not is_valid_user(session['token']):
        return jsonify({'success': False, 'msg': 'Unauthorized'}), 401
    
    try:
        username = session['username']
        
        # Get all user data WITH encrypted message content
        user_data = db.export_user_data_gdpr(username)
        
        logger.info(f"[GDPR] Data exported for: {username} (encrypted, for client-side decryption)")
        
        return jsonify({
            'success': True,
            'data': user_data
        })
        
    except Exception as e:
        logger.error(f"[GDPR] Export error: {e}")
        return jsonify({'success': False, 'msg': str(e)}), 500
           
@app.route('/health')
def health():
    """
    Health check endpoint for monitoring.
    
    Returns:
        JSON: {'status': 'ok', 'users': int, 'rooms': int}
    
    Note:
        Used for uptime monitoring and basic system stats.
    """
    return jsonify({'status': 'ok', 'users': len(load_users()), 'rooms': len(db.list_public_rooms())})

# Add this route to serve static files
@app.route('/static/<path:filename>')
def serve_static(filename):
    """
    Serve static files (CSS, JavaScript, images).
    
    Flask route to deliver static assets like stylesheets and client-side
    scripts from the /static directory.
    
    Args:
        filename (str): Path to file within static directory
    
    Returns:
        File: Requested static file
    
    Note:
        Flask has built-in static file serving, but this route provides
        explicit control over static file delivery.
    """
    return send_from_directory('static', filename)

# ===== SOCKET.IO HANDLERS =====

@socketio.on('connect')
def handle_connect(auth):
    """
    Handle new WebSocket connection and initiate key exchange.
    
    Verifies user authentication, checks room membership, handles duplicate
    connections, and starts Diffie-Hellman key exchange process.
    
    Auth Data:
        token (str): User session token
        room_id (str): Room to join (optional, None for hub connections)
    
    Returns:
        None (emits 'error' or 'dh_pub' events)
    
    Note:
        Automatically disconnects old sessions from same user in same room.
    """
    token = auth.get('token')
    room_id = auth.get('room_id')
    
    if not token or not is_valid_user(token):
        emit('error', {'msg': 'Invalid session'})
        return False
    
    username = get_username_from_token(token)
    sid = request.sid
    
    if not room_id:
        connections[sid] = {
            'username': username,
            'token': token,
            'room_id': None
        }
        join_room('hub')
        return
    
    role = db.get_member_role(room_id, username)
    if not role:
        emit('error', {'msg': 'Not a member of this room'})
        return False
    
    # Force disconnect old sessions in same room
    if username in active_sids:
        for old_sid in active_sids[username][:]:
            if old_sid in connections and connections[old_sid].get('room_id') == room_id:
                try:
                    emit('force_disconnect', room=old_sid)
                except:
                    pass
                if old_sid in connections:
                    del connections[old_sid]
                if room_id in room_sids and old_sid in room_sids[room_id]:
                    room_sids[room_id].remove(old_sid)
    
    if username not in active_sids:
        active_sids[username] = []
    active_sids[username].append(sid)
    
    if room_id not in room_sids:
        room_sids[room_id] = []
    room_sids[room_id].append(sid)
    
    connections[sid] = {
        'username': username,
        'token': token,
        'room_id': room_id,
        'priv_key': None,
        'ready': False,
        'key_version': -1,
        'connect_time': time.time()
    }
    
    join_room(room_id)

    # Mark user as online
    db.set_user_online_status(username, room_id, True)
    
    logger.info(f"[CONNECT] {username} joined room {room_id} ({sid}) [ONLINE]")
    
    # Start DH key exchange
    def start_dh():
        try:
            param_nums = parameters.parameter_numbers()
            p, g = param_nums.p, param_nums.g
            priv_exp = int.from_bytes(os.urandom((p.bit_length() + 7) // 8), 'big') % (p - 2) + 2
            pub_exp = pow(g, priv_exp, p)
            priv_numbers = dh.DHPrivateNumbers(priv_exp, dh.DHPublicNumbers(pub_exp, param_nums))
            priv_key = priv_numbers.private_key(backend)
            pub_key = priv_key.public_key()
            pub_num = pub_key.public_numbers()
            
            connections[sid]['priv_key'] = priv_key
            pub_bytes = pub_num.y.to_bytes((pub_num.y.bit_length() + 7) // 8, 'big')
            socketio.emit('dh_pub', {'pub': pub_bytes.hex()}, room=sid)
            logger.info(f"[DH] Sent public key to {sid}")
        except Exception as e:
            logger.error(f"[DH] Key generation failed for {sid}: {e}")
            socketio.emit('error', {'msg': 'Key exchange failed'}, room=sid)
    
    threading.Thread(target=start_dh, daemon=True).start()

@socketio.on('dh_peer')
def handle_dh_peer(data):
    """
    Complete DH handshake with client (prepares for P2P key sharing).
    
    The client sends their DH public key to complete the exchange. This
    establishes that the client has generated their DH keypair, which they'll
    later use for peer-to-peer key sharing with other members.
    
    Note: The server does NOT need to derive or store any keys from this
    exchange. The client's DH private key is used exclusively for P2P
    encryption between clients, not for client-server communication.
    
    Data:
        pub (str): Client's DH public key as hex string
    
    Emits:
        'generate_group_key': If user is first member (tells them to create key)
        'check_for_stored_key': If user is joining existing room (checks localStorage)
        'error': If DH validation fails
    """
    sid = request.sid
    if sid not in connections:
        emit('error', {'msg': 'Session lost'})
        return
    
    try:
        # Verify client sent valid DH public key
        pub_hex = data.get('pub', '')
        if not pub_hex:
            raise ValueError('No public key received')
        
        # Basic validation only
        peer_pub_bytes = bytes.fromhex(pub_hex)
        param_nums = parameters.parameter_numbers()
        p = param_nums.p
        peer_pub_int = int.from_bytes(peer_pub_bytes, 'big')
        
        if not (1 < peer_pub_int < p):
            raise ValueError('Invalid public key range')
        
        # Mark as ready (client has completed DH setup for P2P)
        connections[sid]['priv_key'] = None  # Clear server's temp key
        connections[sid]['ready'] = True
        
        logger.info(f"[DH] Client {sid} ready for P2P key sharing")
        
        # Determine next step
        room_id = connections[sid]['room_id']
        username = connections[sid]['username']
        
        # Check if room key EXISTS (not just member count!)
        # This prevents regenerating keys on reconnection
        if room_id in room_keys and room_keys[room_id].get('version') is not None:
            # Room already has a key - check if user has it in localStorage
            current_version = room_keys[room_id]['version']
            logger.info(f"[E2EE] {username} reconnecting - room has key v{current_version}, checking localStorage")
            emit('check_for_stored_key', {
                'room_id': room_id,
                'key_version': current_version
            })
        else:
            # No key exists yet - this is the FIRST EVER connection to this room
            # User should generate the initial key
            logger.info(f"[E2EE] {username} is FIRST EVER - requesting client key generation")
            emit('generate_group_key', {'room_id': room_id, 'key_version': 0})
            
    except Exception as e:
        logger.error(f"[DH] Failed for {sid}: {e}")
        emit('error', {'msg': f'Key exchange failed: {str(e)}'})
                                           
@socketio.on('client_ready')
def handle_client_ready():
    """Client confirms ready after receiving initial key"""
    sid = request.sid
    if sid not in connections:
        return
    
    username = connections[sid]['username']
    room_id = connections[sid]['room_id']
    
    # Broadcast join message
    emit('sys_msg', {'type': 'joined', 'user': username}, to=room_id, include_self=False, broadcast=True)
    broadcast_member_update(room_id)
    
    # Send history
    try:
        members = db.get_room_members(room_id)
        user_member = next((m for m in members if m['username'] == username), None)
        if user_member:
            first_join = user_member['first_join_at']
            _, key_version = room_manager.get_room_key(room_id)
            messages = db.get_messages_after_timestamp(room_id, first_join, limit=51)
            
            emit('message_history', {
                'messages': [{
                    'id': msg['id'],
                    'sender': msg['sender'],
                    'enc': msg['encrypted_content'],
                    'timestamp': msg['timestamp'],
                    'key_version': msg['key_version'],
                    'reactions': msg['reactions'],
                    'files': json.loads(msg['file_metadata']) if msg['file_metadata'] else []
                } for msg in messages],
                'current_key_version': key_version
            })
    except Exception as e:
        logger.error(f"[HISTORY] Failed: {e}")

@socketio.on('submit_group_key')
def handle_submit_group_key(data):
    """
    Receive and store client-generated encryption key (TRUE E2EE).
    
    This is called when a client generates a new room encryption key and sends
    it back to the server. In true end-to-end encryption, the server receives
    only the key version number; the client retains the actual group key.
    
    The server stores:
    - Key version number
    - Generator username (for finding key sharers later)
    
    Socket Event Data:
        key_version (int): Key version number (typically 0 for first key)
    
    Emits:
        'sys_msg': Join notification to all room members
        'message_history': Empty history array (first member has no history)
    
    Side Effects:
        - Updates room_keys dict in memory
        - Updates key_version in database
        - Broadcasts member list update
    
    Note:
        This is the FIRST step in client-side key generation. The client will
        then share this key with other members using peer-to-peer DH encryption.
    """
    sid = request.sid
    if sid not in connections:
        return
    
    username = connections[sid]['username']
    room_id = connections[sid]['room_id']
    key_version = data.get('key_version', 0)
    
    room_lock = get_room_lock(room_id)
    with room_lock:
        room_keys[room_id] = {
            'version': key_version,
            'generator': username
        }
        db.update_room_key_version(room_id, key_version)
    
    emit('sys_msg', {'type': 'joined', 'user': username}, to=room_id, include_self=True, broadcast=True)
    broadcast_member_update(room_id)
    emit('message_history', {'messages': [], 'current_key_version': key_version})

@socketio.on('request_user_public_key')
def handle_request_user_public_key(data):
    """
    Request a user's DH public key for peer-to-peer key sharing.
    
    When a user needs to share the group encryption key with another member,
    they first need that member's DH public key to encrypt the key. This
    handler relays the request to the target user.
    
    This is part of the peer-to-peer key distribution protocol:
    1. Key sharer requests target's public key (THIS HANDLER)
    2. Target sends their public key back
    3. Sharer encrypts group key with shared secret
    4. Sharer sends encrypted group key to target
    
    Socket Event Data:
        sid (str): Target user's socket ID
        key_version (int): Which key version to share
    
    Emits:
        'send_public_key_to_peer': Request to target user to send their public key
    
    Note:
        This ensures end-to-end encryption - the server never sees the plaintext
        group key, only encrypted blobs passing between peers.
    """
    target_sid = data.get('sid')
    requester_sid = request.sid
    key_version = data.get('key_version')
    requester_name = connections[requester_sid]['username']
    
    socketio.emit('send_public_key_to_peer', {
        'requester_sid': requester_sid,
        'requester_username': requester_name,
        'key_version': key_version
    }, to=target_sid)

@socketio.on('public_key_for_peer')
def handle_public_key_for_peer(data):
    """
    Relay a user's DH public key back to the key sharer.
    
    After receiving a public key request (from handle_request_user_public_key),
    the target user sends their DH public key. This handler relays it back to
    the original requester (key sharer).
    
    This is step 2 of the peer-to-peer key sharing protocol.
    
    Socket Event Data:
        requester_sid (str): Socket ID of user who needs the public key
        public_key (str): DH public key as hex string
        key_version (int): Key version being shared
    
    Emits:
        'user_public_key': Sends public key to the original requester
    
    Note:
        The server is just a relay here - it doesn't perform any crypto operations
        on the public key, just passes it along.
    """
    sender_sid = request.sid
    sender_name = connections[sender_sid]['username']
    requester_sid = data.get('requester_sid')
    
    socketio.emit('user_public_key', {
        'username': sender_name,
        'sid': sender_sid,
        'public_key': data.get('public_key'),
        'key_version': data.get('key_version')
    }, to=requester_sid)

@socketio.on('deliver_shared_key')
def handle_deliver_shared_key(data):
    """
    Relay encrypted group key from sharer to recipient.
    
    After the key sharer receives the target's public key and encrypts the
    group key with their shared DH secret, this handler relays the encrypted
    key to the recipient.
    
    This is the final step (step 4) of peer-to-peer key sharing.
    
    Socket Event Data:
        target_sid (str): Recipient's socket ID
        encrypted_key (str): Group key encrypted with P2P shared secret
        key_version (int): Key version number
        our_public_key (str): Sharer's DH public key (for recipient to derive shared secret)
    
    Emits:
        'group_key_from_peer': Delivers encrypted key to recipient
    
    Note:
        The server cannot decrypt this key blob - it's encrypted with a shared
        secret derived from DH exchange between the two peers. Only the recipient
        can decrypt it.
    """
    sender_sid = request.sid
    sender_username = connections[sender_sid]['username']
    target_sid = data.get('target_sid')
    
    # Use client-provided public key (client sends it now!)
    socketio.emit('group_key_from_peer', {
        'encrypted_key': data.get('encrypted_key'),
        'key_version': data.get('key_version'),
        'sharer_username': sender_username,
        'sharer_public_key': data.get('our_public_key')  # From client!
    }, to=target_sid)

@socketio.on('request_key_from_peers')
def handle_request_key_from_peers(data):
    """
    Request encryption key from ANY online member (not just generator).
    
    Called when a client doesn't have a key in localStorage and needs to
    request it from the room. Finds ANY online member (not just the original generator),
    making the system more resilient to generator offline situations.
    
    How it works:
    1. Find ANY ready member in the room (has key, is ready)
    2. Ask that member to share the key with this user
    3. Member shares key using P2P DH encryption
    
    Socket Event Data:
        key_version (int): Which key version is needed
    
    Emits:
        'request_key_share': Asks found member to share key
        'error': If no online members have the key
    
    Note:
        This fixes the "Key distributor offline" issue - now ANY member can
        distribute keys, not just the room creator
    """
    sid = request.sid
    if sid not in connections:
        return
    
    username = connections[sid]['username']
    room_id = connections[sid]['room_id']
    key_version = data.get('key_version', 0)
    
    logger.info(f"[E2EE] {username} needs key v{key_version}, finding someone who has it")
    
    # Find ANY ready member in the room (not just generator)
    found_sharer = False
    for member_sid, conn in connections.items():
        if (conn.get('room_id') == room_id and 
            conn.get('ready') and 
            member_sid != sid):
            
            # Ask this member to share the key
            member_name = conn['username']
            logger.info(f"[E2EE] Asking {member_name} to share key v{key_version} with {username}")
            socketio.emit('request_key_share', {
                'target_username': username,
                'target_sid': sid,
                'key_version': key_version
            }, to=member_sid)
            found_sharer = True
            break  # Only need one person to share
    
    if not found_sharer:
        logger.error(f"[E2EE] No one online has key v{key_version}!")
        emit('error', {'msg': 'No members online have the encryption key. Please wait for someone to rejoin or ask the room admin.'})

@socketio.on('message')
def handle_message(data):
    """
    Receive and broadcast an encrypted message.
    
    Validates user is ready, stores encrypted message in database with
    current key version, then broadcasts to all room members. Supports
    multiple file attachments per message.
    
    Data:
        enc (str): Hex-encoded encrypted message (IV + ciphertext)
        files (list, optional): Array of file metadata dicts for attachments
        file_metadata (dict, optional): Legacy single file support (deprecated)
    
    Emits:
        'error' on validation failure
        'encrypted_msg' to room on success
    
    Note:
        Server never decrypts content - true end-to-end encryption.
    """
    sid = request.sid
    if sid not in connections:
        emit('error', {'msg': 'Not connected'})
        return
    
    conn = connections[sid]
    username = conn['username']
    room_id = conn['room_id']
    
    # Check ready state
    if not conn.get('ready'):
        emit('error', {'msg': 'Not ready to send messages. Please wait...'})
        logger.warning(f"[MSG] {username} tried to send but not ready")
        return
    
    enc_msg = data.get('enc', '')
    files = data.get('files', [])

    if not enc_msg and not files:
        emit('error', {'msg': 'Empty message'})
        return
    
    try:
        # Get current key version (TRUE E2EE - no plaintext key!)
        room_lock = get_room_lock(room_id)
        with room_lock:
            _, key_version = room_manager.get_room_key(room_id)
            
            # Just check if room has a key version
            if room_id not in room_keys:
                emit('error', {'msg': 'Room key not available'})
                return
            
            # Save message to database FIRST
            # Convert files array to JSON for storage
            files_json = json.dumps(files) if files else None
            msg_id = db.save_message(room_id, username, enc_msg, key_version, files_json)
            
            # Create message payload
            msg_payload = {
                'id': msg_id,
                'sender': username,
                'enc': enc_msg,
                'timestamp': datetime.datetime.now().timestamp(),
                'key_version': key_version,
                'files': files,  # Send as array
                'reactions': {}
            }
            
            logger.info(f"[MSG] {username} sent message in {room_id} (id: {msg_id}), broadcasting to room")
            
            # THE FIX: Use emit with 'to' parameter for room broadcasting
            # This broadcasts to ALL clients in the Socket.IO room
            emit('encrypted_msg', msg_payload, to=room_id, include_self=True, broadcast=True)
            
            logger.info(f"[MSG] Broadcasted message {msg_id} to all members in room {room_id}")
            
    except Exception as e:
        logger.error(f"[MSG] Error: {e}")
        import traceback
        traceback.print_exc()
        emit('error', {'msg': 'Failed to send message'})

@socketio.on('load_more_messages')
def handle_load_more(data):
    """
    Handle pagination request for older messages.
    
    Loads next batch of message history before a specific message ID.
    Used for infinite scroll / "load more" functionality.
    
    Data:
        before_id (int): Load messages older than this ID
    
    Emits:
        'more_messages' with next batch of encrypted messages
    """
    sid = request.sid
    if sid not in connections:
        return
    
    room_id = connections[sid]['room_id']
    username = connections[sid]['username']
    before_id = data.get('before_id')
    
    members = db.get_room_members(room_id)
    user_member = next((m for m in members if m['username'] == username), None)
    if not user_member:
        return
    
    first_join = user_member['first_join_at']
    messages = db.get_messages(room_id, first_join, limit=50, before_id=before_id)
    
    emit('more_messages', {
        'messages': [{
            'id': msg['id'],
            'sender': msg['sender'],
            'enc': msg['encrypted_content'],
            'timestamp': msg['timestamp'],
            'key_version': msg['key_version'],
            'reactions': msg['reactions'],
            'files': json.loads(msg['file_metadata']) if msg['file_metadata'] else []
        } for msg in messages]
    })

@socketio.on('upload_file')
def handle_file_upload(data):
    """
    Receive and save an uploaded file (encrypted or unencrypted).
    
    Supports TRUE E2EE file encryption where files are encrypted client-side
    before upload. Server stores encrypted blob and cannot decrypt.
    """
    sid = request.sid
    if sid not in connections:
        emit('upload_error', {'msg': 'Not connected'})
        return
    
    try:
        # Decode the base64 file data (may be encrypted!)
        file_data = base64.b64decode(data['file_data'])
        filename = secure_filename(data['filename']) or 'uploaded_file'
        content_type = data.get('content_type', 'application/octet-stream')
        key_version = data.get('key_version', 0)
        is_encrypted = data.get('is_encrypted', False)
        
        # Check file size (encrypted files are larger)
        max_size = 22 * 1024 * 1024 if is_encrypted else 16 * 1024 * 1024
        if len(file_data) > max_size:
            emit('upload_error', {'msg': f'File too large (max {max_size // (1024*1024)}MB)'})
            return
        
        # Check file type
        if not allowed_file(filename):
            emit('upload_error', {'msg': 'File type not allowed'})
            return
        
        # Generate unique file ID
        import secrets
        file_id = f"file_{secrets.token_hex(16)}"
        
        # Save file to uploads folder (encrypted or plain)
        file_path = UPLOAD_FOLDER / f"{file_id}_{filename}"
        with open(file_path, 'wb') as f:
            f.write(file_data)
        
        emit('file_uploaded', {
            'file_id': file_id,
            'filename': filename,
            'size': len(file_data),
            'content_type': content_type,
            'key_version': key_version,
            'is_encrypted': is_encrypted
        })
        
        logger.info(f"[FILE] Saved {filename} ({'ENCRYPTED' if is_encrypted else 'PLAIN'}) - ID: {file_id}")
    except Exception as e:
        logger.error(f"[FILE] Upload error: {e}")
        emit('upload_error', {'msg': f'File upload failed: {str(e)}'})

@socketio.on('delete_uploaded_file')
def handle_delete_uploaded_file(data):
    """
    Delete an uploaded file that was never sent (user removed it from preview).
    
    Called when user clicks the remove button on a pending file attachment
    before sending the message. Cleans up the server-side orphaned file.
    
    Socket Event Data:
        file_id (str): ID of the file to delete (format: file_<hex>)
    
    Emits:
        'file_delete_error': If file_id is invalid or file not found
    """
    sid = request.sid
    if sid not in connections:
        return
    
    file_id = data.get('file_id', '')
    
    # Validate format to prevent path traversal
    if not file_id or not file_id.startswith('file_'):
        return
    
    import glob
    matching_files = glob.glob(str(UPLOAD_FOLDER / f"{file_id}_*"))
    
    for file_path in matching_files:
        try:
            Path(file_path).unlink()
            logger.info(f"[FILE] Deleted orphaned file on user cancel: {file_path}")
        except Exception as e:
            logger.error(f"[FILE] Failed to delete orphaned file {file_path}: {e}")
        
@socketio.on('delete_message')
def handle_delete_message(data):
    """
    Soft-delete a message.
    
    Verifies authorization (sender, room admin, or global admin) then
    marks message as deleted and broadcasts deletion to room.
    
    Data:
        message_id (int): Message to delete
    
    Emits:
        'error' if unauthorized
        'message_deleted' to room on success
    """
    sid = request.sid
    if sid not in connections:
        return
    
    msg_id = data.get('message_id')
    username = connections[sid]['username']
    room_id = connections[sid]['room_id']
    token = connections[sid]['token']
    
    msg_info = db.get_message_sender(msg_id)
    if not msg_info or msg_info['room_id'] != room_id:
        emit('error', {'msg': 'Message not found'})
        return
    
    is_sender = msg_info['sender'] == username
    is_room_admin = db.get_member_role(room_id, username) == 'admin'
    is_global = is_global_admin(token)
    
    if not (is_sender or is_room_admin or is_global):
        emit('error', {'msg': 'Not authorized'})
        return
    
    success = db.delete_message(msg_id, username)
    if success:
        emit('message_deleted', {'message_id': msg_id, 'deleted_by': username}, room=room_id, include_self=True)
        logger.info(f"[DELETE] Message {msg_id} deleted by {username}")

@socketio.on('react')
def handle_reaction(data):
    """
    Add or remove emoji reaction on a message.
    
    Toggles user's reaction (add if not present, remove if already exists)
    and broadcasts updated reaction counts to room.
    
    Data:
        message_id (int): Message to react to
        emoji (str): Emoji character
        action (str): 'add' or 'remove'
    
    Emits:
        'reaction_update' to room with all reactions for the message
    """
    sid = request.sid
    if sid not in connections:
        return
    
    msg_id = data.get('message_id')
    emoji = data.get('emoji')
    action = data.get('action', 'add')
    username = connections[sid]['username']
    room_id = connections[sid]['room_id']
    
    if action == 'add':
        success = db.add_reaction(msg_id, username, emoji)
    else:
        success = db.remove_reaction(msg_id, username, emoji)
    
    if success:
        msg_reactions = db.get_message_reactions(msg_id)
        
        emit('reaction_update', {
            'message_id': msg_id,
            'emoji': emoji,
            'username': username,
            'action': action,
            'all_reactions': msg_reactions
        }, room=room_id, include_self=True)
        
        logger.info(f"[REACT] {username} {action}ed {emoji} to msg {msg_id}")

@socketio.on('kick_user')
def handle_kick(data):
    """
    Kick a user from room and trigger client-side key rotation.
    
    This is the server-side handler for kicking users. It:
    1. Verifies admin authorization
    2. Removes user from database (member list, reactions)
    3. Disconnects their socket connections
    4. Increments key version in database
    5. Signals admin (kicker) to generate NEW key client-side
    
    In TRUE E2EE, key rotation happens CLIENT-SIDE:
    - Admin generates new random key
    - Admin shares it with remaining members P2P
    - Server never sees the new key
    
    Socket Event Data:
        user (str): Username to kick
    
    Emits:
        'error': If not authorized or user not in room
        'kicked': To the kicked user's socket (forces disconnect)
        'sys_msg': Kick notification to room
        'rotate_group_key': To admin, signals client-side key generation
        'reactions_cleaned': Notification to refresh reactions UI
    
    Side Effects:
        - Removes user from database (room_members, reactions)
        - Increments key_version in database
        - Updates room_keys dict in memory
        - Disconnects kicked user's sockets
    
    Authorization:
        Room admin or global admin only
    """
    sid = request.sid
    if sid not in connections:
        return
    
    conn = connections[sid]
    room_id = conn['room_id']
    kicked_user = data.get('user', '')
    
    success, _, msg = room_manager.kick_user(room_id, conn['token'], kicked_user)
    
    if not success:
        emit('error', {'msg': msg})
        return
    
    logger.info(f"[KICK] {kicked_user} kicked from {room_id}")
    _, new_version = room_manager.get_room_key(room_id)
    
    # Remove kicked user from room_sids FIRST
    kicked_sids = []
    if kicked_user in active_sids:
        for s in active_sids[kicked_user][:]:
            if s in connections and connections[s].get('room_id') == room_id:
                kicked_sids.append(s)
    
    # Remove from room_sids before key rotation
    for s in kicked_sids:
        if room_id in room_sids and s in room_sids[room_id]:
            room_sids[room_id].remove(s)
    
    # Kick user(s) immediately
    for s in kicked_sids:
        try:
            socketio.emit('kicked', {'msg': msg}, to=s)
            leave_room(room_id, s)
        except:
            pass
        if s in connections:
            del connections[s]
    
    # Notify room
    emit('sys_msg', {'type': 'kicked', 'user': kicked_user, 'msg': msg}, to=room_id, include_self=True, broadcast=True)
    
    # TRUE E2EE: Ask kicker (admin) to generate new key
    socketio.emit('rotate_group_key', {
        'new_version': new_version,
        'kicked_user': kicked_user
    }, to=sid)
    
    broadcast_room_update()
    broadcast_member_update(room_id)

    socketio.emit('reactions_cleaned', {
        'username': kicked_user,
        'msg': f'{kicked_user} was removed from the room'
    }, to=room_id)

@socketio.on('request_key_share_for_rotation')
def handle_request_key_share_for_rotation(data):
    """
    Request member's public key for distributing rotated encryption key.
    
    After key rotation (when a user is kicked), the admin who generated the
    new key needs to share it with remaining members. This handler facilitates
    requesting each member's DH public key so the admin can encrypt the new
    key for them.
    
    This is identical to handle_request_user_public_key but specifically for
    the key rotation scenario.
    
    Socket Event Data:
        target_username (str): Member to request public key from
        key_version (int): New key version being distributed
    
    Emits:
        'send_public_key_to_peer': Request to member for their public key
    
    Note:
        Called multiple times (once per remaining member) during key rotation
        to distribute the new key to everyone except the kicked user.
    """
    sender_sid = request.sid
    target_username = data.get('target_username')
    key_version = data.get('key_version')
    sender_name = connections[sender_sid]['username']
    room_id = connections[sender_sid]['room_id']
    
    # Find target's socket
    target_sid = None
    for sid, conn in connections.items():
        if conn.get('username') == target_username and conn.get('room_id') == room_id:
            target_sid = sid
            break
    
    if target_sid:
        socketio.emit('send_public_key_to_peer', {
            'requester_sid': sender_sid,
            'requester_username': sender_name,
            'key_version': key_version
        }, to=target_sid)

@socketio.on('leave_room')
def handle_leave_room():
    """
    Handle user voluntarily leaving a room.
    
    Removes user from room, handles admin succession if needed, broadcasts
    departure notification. Does NOT rotate key (voluntary exit).
    
    Emits:
        'sys_msg' (admin transfer if applicable)
        'sys_msg' (leave notification)
        'room_left' confirmation to user
    """
    sid = request.sid
    if sid not in connections:
        return
    
    username = connections[sid]['username']
    room_id = connections[sid]['room_id']
    
    success, new_admin, msg = room_manager.leave_room(room_id, username)
    
    if success:
        if new_admin:
            emit('sys_msg', {'type': 'admin_transfer', 'user': new_admin, 'msg': f'{new_admin} is now admin'}, room=room_id, include_self=True)
        
        emit('sys_msg', {'type': 'left', 'user': username, 'msg': f'{username} left'}, room=room_id, include_self=False)
        leave_room(room_id, sid)
        
        if room_id in room_sids and sid in room_sids[room_id]:
            room_sids[room_id].remove(sid)
        
        emit('room_left', {'msg': msg})
        broadcast_room_update()
        broadcast_member_update(room_id)

        # Notify room to refresh reactions (removed leaving user's reactions)
        socketio.emit('reactions_cleaned', {
            'username': username,
            'msg': f'{username} left the room'
        }, to=room_id, include_self=False)
        
        logger.info(f"[LEAVE] {username} left {room_id}")

@socketio.on('typing_start')
def handle_typing_start():
    """
    Handle user started typing event.
    
    Broadcasts typing status to all other users in the room.
    Does not send to the user who is typing (include_self=False).
    
    Emits:
        'user_typing' to room with is_typing=True
    """
    sid = request.sid
    if sid not in connections:
        return
    
    username = connections[sid]['username']
    room_id = connections[sid]['room_id']
    
    # Broadcast to everyone except sender
    emit('user_typing', {
        'username': username,
        'is_typing': True
    }, to=room_id, include_self=False)
    
    logger.debug(f"[TYPING] {username} started typing in {room_id}")

@socketio.on('typing_stop')
def handle_typing_stop():
    """
    Handle user stopped typing event.
    
    Broadcasts to room that user is no longer typing. Called when:
    - User hasn't typed for 2 seconds
    - User sends a message
    - User clears the input field
    
    Emits:
        'user_typing' to room with is_typing=False
    """
    sid = request.sid
    if sid not in connections:
        return
    
    username = connections[sid]['username']
    room_id = connections[sid]['room_id']
    
    # Broadcast to everyone except sender
    emit('user_typing', {
        'username': username,
        'is_typing': False
    }, to=room_id, include_self=False)
    
    logger.debug(f"[TYPING] {username} stopped typing in {room_id}")

@socketio.on('disconnect')
def handle_disconnect():
    """
    Clean up when user disconnects (closes browser, loses connection).
    
    Removes connection from tracking dicts, broadcasts disconnect notification
    to room, removes from room's socket ID list, and marks user as offline.
    
    Emits:
        'sys_msg' (disconnected notification) to room
        'member_list_update' with updated online status
    
    Note:
        User's membership persists - they can reconnect and rejoin with
        same message history access.
    """
    sid = request.sid
    if sid in connections:
        username = connections[sid]['username']
        room_id = connections[sid].get('room_id')
        
        if username in active_sids:
            active_sids[username] = [s for s in active_sids[username] if s != sid]
            if not active_sids[username]:
                del active_sids[username]
        
        if room_id:
            # Mark user as offline
            db.set_user_online_status(username, room_id, False)
            
            if room_id in room_sids and sid in room_sids[room_id]:
                room_sids[room_id].remove(sid)
            
            emit('sys_msg', {'type': 'disconnected', 'user': username}, room=room_id, include_self=False)
            
            # Broadcast updated member list with online status
            broadcast_member_update(room_id)
            
            leave_room(room_id, sid)
        
        del connections[sid]
        logger.info(f"[DISCONNECT] {username} [OFFLINE]")

# ===== POPULATE ROOM_KEYS FROM DATABASE ON STARTUP =====
logger.info("[STARTUP] Loading room key versions from database...")
try:
    all_rooms = db.list_all_rooms()  # Get all rooms from DB
    for room_info in all_rooms:
        room_id = room_info['id']
        key_version = room_info.get('current_key_version', 0)
        
        # Find the creator (generator) - use first admin
        members = db.get_room_members(room_id)
        admin_member = next((m for m in members if m['role'] == 'admin'), None)
        generator = admin_member['username'] if admin_member else 'unknown'
        
        # Populate room_keys dict with version info
        # (encrypted_key is None because server never has plaintext key in TRUE E2EE)
        room_keys[room_id] = {
            'encrypted_key': None,
            'version': key_version,
            'generator': generator
        }
        logger.info(f"[STARTUP] Loaded room {room_id}: key v{key_version}, generator={generator}")
    
    logger.info(f"[STARTUP] Loaded {len(room_keys)} room key versions from database")
except Exception as e:
    logger.error(f"[STARTUP] Failed to load room keys: {e}")
# ===== END ROOM_KEYS POPULATION =====

logger.info("="*60)
logger.info("STARTING SERVER - Fresh Instance")
logger.info(f"Database: {db.DB_PATH}")
logger.info(f"Room keys in memory: {len(room_manager.room_keys) if hasattr(room_manager, 'room_keys') else 0}")
logger.info("="*60)

if __name__ == '__main__':
    host = config.get('host', 'localhost')
    port = config.get('port', 5000)
    socketio.run(app, host=host, port=port, debug=app.config['DEBUG'])