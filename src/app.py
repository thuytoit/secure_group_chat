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
from users import register, login, is_admin as is_global_admin, logout, load_users
from rooms import room_manager
import database as db
from crypto import parameters, derive_key, encrypt_message
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

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', max_http_buffer_size=20*1024*1024)

logging.basicConfig(level=logging.INFO if app.config['DEBUG'] else logging.WARNING)
logger = logging.getLogger(__name__)

connections = {}
active_sids = {}
room_sids = {}
backend = default_backend()

# Key management locks
key_locks = {}
connection_locks = threading.Lock()

# Thread pool for crypto operations
key_executor = ThreadPoolExecutor(max_workers=10)

def cleanup():
    """Clean up on shutdown"""
    logger.info("[SHUTDOWN] Closing database connections...")
    db.close_db()

def get_username_from_token(token: str) -> str | None:
    users = load_users()
    for u, data in users.items():
        if data.get('token') == token:
            return u
    return None

def is_valid_user(token: str) -> bool:
    return get_username_from_token(token) is not None

def require_auth():
    if 'token' not in session or not is_valid_user(session['token']):
        return redirect(url_for('index'))
    return None

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def broadcast_room_update():
    """Broadcast room list update to all users"""
    public_rooms = room_manager.list_public_rooms()
    socketio.emit('room_list_update', {'public_rooms': public_rooms}, namespace='/')
    
    for sid, conn in list(connections.items()):
        if conn.get('username'):
            user_rooms = room_manager.list_user_rooms(conn['username'])
            socketio.emit('user_rooms_update', {'user_rooms': user_rooms}, room=sid)

def broadcast_member_update(room_id: str):
    """Broadcast updated member list to room"""
    members = db.get_room_members(room_id)
    socketio.emit('member_list_update', {
        'members': [{
            'username': m['username'],
            'role': m['role'],
            'joined_at': m['joined_at']
        } for m in members]
    }, to=room_id)

def broadcast_reports_update():
    """Broadcast updated reports to all connected clients"""
    try:
        pending_reports = room_manager.get_pending_reports()
        socketio.emit('reports_updated', {'pending_reports': pending_reports})
    except Exception as e:
        logger.error(f"Report broadcast error: {e}")

def get_room_lock(room_id: str):
    """Get or create a lock for a specific room"""
    with connection_locks:
        if room_id not in key_locks:
            key_locks[room_id] = threading.Lock()
        return key_locks[room_id]

def send_group_key_to_user(sid: str, room_id: str, username: str, status: str = 'initial'):
    """
    Send group key(s) to a single user with historical key support.
    For reconnecting users, sends ALL needed key versions.
    """
    if sid not in connections:
        logger.error(f"[KEY] Socket {sid} not found in connections")
        return False
    
    conn = connections[sid]
    
    if not conn.get('user_key'):
        logger.error(f"[KEY] No user key for {username}")
        return False
    
    try:
        # Get current room key
        room_lock = get_room_lock(room_id)
        with room_lock:
            current_key, current_version = room_manager.get_room_key(room_id)
            if not current_key:
                logger.error(f"[KEY] No room key for {room_id}")
                return False
            
            # Check if user needs historical keys (reconnection after key rotation)
            members = db.get_room_members(room_id)
            user_member = next((m for m in members if m['username'] == username), None)
            
            needed_versions = set()
            
            if user_member and status == 'initial':
                # Get all messages since user's first join to find needed key versions
                first_join = user_member['first_join_at']
                messages = db.get_messages_after_timestamp(room_id, first_join, limit=1000)
                
                for msg in messages:
                    needed_versions.add(msg['key_version'])
                
                # Also include current version
                needed_versions.add(current_version)
                
                logger.info(f"[KEY] {username} needs key versions: {sorted(needed_versions)} for history since {first_join}")
            else:
                # New join or key rotation - just send current key
                needed_versions.add(current_version)
            
            # Send all needed keys
            keys_to_send = sorted(needed_versions)
            
            for idx, version in enumerate(keys_to_send):
                # Regenerate historical key deterministically
                key_to_send = room_manager._derive_room_key(room_id, version)
                
                # Encrypt with user's key
                enc_data = encrypt_message(key_to_send, conn['user_key'])
                
                # Determine status for this key
                is_last = (idx == len(keys_to_send) - 1)
                
                if len(keys_to_send) == 1:
                    # Only one key - use the original status
                    key_status = status
                elif is_last:
                    # Last key in batch - use 'initial' so client becomes ready
                    key_status = 'initial'
                else:
                    # Historical key - client will store but not become ready yet
                    key_status = 'historical'
                
                # Send this key version
                socketio.emit('group_key', {
                    'enc': enc_data.hex(),
                    'version': version,
                    'status': key_status,
                    'total_keys': len(keys_to_send),  # NEW: Tell client how many keys to expect
                    'key_index': idx + 1  # NEW: Tell client which key this is (1-based)
                }, to=sid)
                
                logger.info(f"[KEY] ✓ Sent v{version} ({key_status}) to {username} [{idx+1}/{len(keys_to_send)}]")
            
            return True
        
    except Exception as e:
        logger.error(f"[KEY] Failed to send key to {username}: {e}")
        import traceback
        traceback.print_exc()
        return False
                
def distribute_new_key_after_kick(room_id: str, new_key: bytes, new_version: int):
    """
    Distribute new key AND all old keys to remaining members after a kick.
    This allows them to decrypt both old and new messages.
    """
    room_lock = get_room_lock(room_id)
    
    with room_lock:
        logger.info(f"[KEY_ROTATION] Starting distribution of v{new_version} for {room_id}")
        
        current_sids = room_sids.get(room_id, []).copy()
        
        logger.info(f"[KEY_ROTATION] Found {len(current_sids)} connections in room")
        
        if not current_sids:
            logger.warning(f"[KEY_ROTATION] No connections to re-key in {room_id}")
            return
        
        # CRITICAL: We need to send ALL key versions, not just the new one
        # Get all previous versions from room_keys history
        
        successful = 0
        for sid in current_sids:
            if sid not in connections:
                continue
                
            conn = connections[sid]
            if not conn.get('user_key'):
                continue
            
            try:
                # Send the new key with 'rotated' status
                enc_data = encrypt_message(new_key, conn['user_key'])
                socketio.emit('group_key', {
                    'enc': enc_data.hex(),
                    'version': new_version,
                    'status': 'rotated'
                }, to=sid)
                successful += 1
                logger.info(f"[KEY_ROTATION] Sent v{new_version} to {conn['username']}")
                
                connections[sid]['key_version'] = new_version
                    
            except Exception as e:
                logger.error(f"[KEY_ROTATION] Failed to send to {conn.get('username')}: {e}")
        
        logger.info(f"[KEY_ROTATION] Completed: {successful}/{len(current_sids)} successful")

def check_connection_health():
    """Periodically check connection health and clean up stale connections"""
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
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def do_register():
    username = request.form['username']
    password = request.form['password']
    success, msg = register(username, password)
    return jsonify({'success': success, 'msg': msg})

@app.route('/login', methods=['POST'])
def do_login():
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
    token = session.get('token')
    if token:
        logout(token)
    session.clear()
    return redirect(url_for('index'))

@app.route('/hub')
def hub():
    redirect_to = require_auth()
    if redirect_to:
        return redirect_to
    
    user_rooms = room_manager.list_user_rooms(session['username'])
    public_rooms = room_manager.list_public_rooms()
    
    pending_reports = []
    if is_global_admin(session['token']):
        pending_reports = room_manager.get_pending_reports()
    
    return render_template('hub.html',
                         username=session['username'],
                         role=session['role'],
                         user_rooms=user_rooms,
                         public_rooms=public_rooms,
                         pending_reports=pending_reports,
                         is_global_admin=is_global_admin(session['token']))

@app.route('/chat/<room_id>')
def chat(room_id):
    redirect_to = require_auth()
    if redirect_to:
        return redirect_to
    
    role = db.get_member_role(room_id, session['username'])
    if not role:
        return redirect(url_for('hub'))
    
    room_info = room_manager.get_room_info(room_id)
    if not room_info:
        return redirect(url_for('hub'))
    
    return render_template('chat.html',
                         username=session['username'],
                         role=session['role'],
                         room_id=room_id,
                         room_name=room_info['name'],
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
        password = data.get('password', '').strip() if data.get('password') else None
        
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

@app.route('/api/rooms/<room_id>/report', methods=['POST'])
def report_room(room_id):
    if 'token' not in session or not is_valid_user(session['token']):
        return jsonify({'success': False, 'msg': 'Unauthorized'}), 401
    
    try:
        data = request.json
        reason = data.get('reason', '').strip()
        details = data.get('details', '').strip()
        
        if not reason:
            return jsonify({'success': False, 'msg': 'Reason required'})
        
        success, msg = room_manager.create_report(room_id, session['username'], reason, details)
        
        if success:
            broadcast_reports_update()
        
        return jsonify({'success': success, 'msg': msg})
    except Exception as e:
        logger.error(f"Report error: {e}")
        return jsonify({'success': False, 'msg': str(e)}), 500

@app.route('/api/reports/<int:report_id>/resolve', methods=['POST'])
def resolve_report_api(report_id):
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

@app.route('/api/files/<file_id>')
def download_file(file_id):
    if 'token' not in session or not is_valid_user(session['token']):
        return jsonify({'success': False, 'msg': 'Unauthorized'}), 401
    
    # Find file in uploads folder
    import glob
    matching_files = glob.glob(str(UPLOAD_FOLDER / f"{file_id}_*"))
    
    if not matching_files:
        return jsonify({'success': False, 'msg': 'File not found'}), 404
    
    file_path = Path(matching_files[0])
    original_filename = file_path.name.split('_', 1)[1]  # Remove "file_xxxxx_" prefix
    
    return send_file(
        file_path,
        download_name=original_filename,
        as_attachment=True
    )
    
@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'users': len(load_users()), 'rooms': len(db.list_public_rooms())})

# Add this route to serve static files
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

# ===== SOCKET.IO HANDLERS =====

@socketio.on('connect')
def handle_connect(auth):
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
        'user_key': None,
        'priv_key': None,
        'ready': False,
        'key_version': -1,
        'connect_time': time.time()
    }
    
    join_room(room_id)
    logger.info(f"[CONNECT] {username} joined room {room_id} ({sid})")
    
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
    sid = request.sid
    if sid not in connections:
        emit('error', {'msg': 'Session lost'})
        return
    
    try:
        priv_key = connections[sid]['priv_key']
        if not priv_key:
            raise ValueError('No private key')
        
        pub_hex = data.get('pub', '')
        if not pub_hex:
            raise ValueError('No public key received')
        
        peer_pub_bytes = bytes.fromhex(pub_hex)
        param_nums = parameters.parameter_numbers()
        p = param_nums.p
        peer_pub_int = int.from_bytes(peer_pub_bytes, 'big')
        
        if not (1 < peer_pub_int < p):
            raise ValueError('Invalid public key range')
        
        peer_pub_num = dh.DHPublicNumbers(peer_pub_int, param_nums)
        peer_pub_key = peer_pub_num.public_key(backend)
        
        # Perform DH exchange
        shared = priv_key.exchange(peer_pub_key)
        
        logger.info(f"[DH] Raw shared secret: {len(shared)} bytes")
        logger.info(f"[DH] Shared secret (first 16 hex): {shared[:8].hex()}")
        
        # Pad/truncate to 32 bytes (matching JavaScript)
        shared_padded = shared.ljust(32, b'\x00')[:32]
        
        logger.info(f"[DH] Padded shared secret (first 16 hex): {shared_padded[:8].hex()}")
        logger.info(f"[DH] Padded shared secret (full 32 bytes hex): {shared_padded.hex()}")
        
        # Derive user key
        user_key = derive_key(shared_padded)
        
        logger.info(f"[DH] User key: {len(user_key)} bytes")
        logger.info(f"[DH] User key (first 16 hex): {user_key[:8].hex()}")  # Changed from 8 to 16 hex chars
        
        # Validate key
        if len(user_key) != 32:
            raise ValueError(f'Invalid user key length: {len(user_key)}')
        
        connections[sid]['user_key'] = user_key
        connections[sid]['priv_key'] = None
        
        logger.info(f"[DH] Exchange complete for {sid}")
        
        # Send group key immediately
        room_id = connections[sid]['room_id']
        username = connections[sid]['username']
        
        if send_group_key_to_user(sid, room_id, username, 'initial'):
            logger.info(f"[DH] Group key sent to {username}")
        else:
            emit('error', {'msg': 'Failed to initialize encryption'})
            
    except Exception as e:
        logger.error(f"[DH] Failed for {sid}: {e}")
        import traceback
        traceback.print_exc()
        emit('error', {'msg': f'Key exchange failed: {str(e)}'})
                                    
@socketio.on('client_ready')
def handle_client_ready():
    """Client confirms they've processed the key and are ready"""
    sid = request.sid
    if sid not in connections:
        return
    
    username = connections[sid]['username']
    room_id = connections[sid]['room_id']
    
    connections[sid]['ready'] = True
    logger.info(f"[READY] {username} is ready in {room_id}")
    
    # Send join notification to others FIRST
    emit('sys_msg', {'type': 'joined', 'user': username}, to=room_id, include_self=False, broadcast=True)
    
    # Update member list
    broadcast_member_update(room_id)
    
    # Send message history
    try:
        members = db.get_room_members(room_id)
        user_member = next((m for m in members if m['username'] == username), None)
        
        if user_member:
            # CRITICAL FIX: Use first_join_at (not joined_at) so continuing members see full history
            first_join = user_member['first_join_at']
            
            # Get the current key version
            _, key_version = room_manager.get_room_key(room_id)
            
            # Get ALL messages since first join
            messages = db.get_messages_after_timestamp(room_id, first_join, limit=100)
            
            # CRITICAL FIX: Don't filter by key version!
            # Users who stayed through key rotation can decrypt both old and new keys
            # Only send messages from their first join onwards
            
            logger.info(f"[HISTORY] Found {len(messages)} messages since first_join_at={first_join}")
            
            emit('message_history', {
                'messages': [{
                    'id': msg['id'],
                    'sender': msg['sender'],
                    'enc': msg['encrypted_content'],
                    'timestamp': msg['timestamp'],
                    'key_version': msg['key_version'],
                    'reactions': msg['reactions'],
                    'file_metadata': msg['file_metadata']
                } for msg in messages],
                'current_key_version': key_version
            })
            logger.info(f"[HISTORY] Sent {len(messages)} messages to {username}")
    except Exception as e:
        logger.error(f"[HISTORY] Failed: {e}")
        import traceback
        traceback.print_exc()

@socketio.on('message')
def handle_message(data):
    sid = request.sid
    if sid not in connections:
        emit('error', {'msg': 'Not connected'})
        return
    
    conn = connections[sid]
    username = conn['username']
    room_id = conn['room_id']
    
    # Check ready state AND user_key
    if not conn.get('ready') or not conn.get('user_key'):
        emit('error', {'msg': 'Not ready to send messages. Please wait...'})
        logger.warning(f"[MSG] {username} tried to send but not ready")
        return
    
    enc_msg = data.get('enc', '')
    file_metadata = data.get('file_metadata')
    
    if not enc_msg and not file_metadata:
        emit('error', {'msg': 'Empty message'})
        return
    
    try:
        # Get current room key with lock
        room_lock = get_room_lock(room_id)
        with room_lock:
            room_key, key_version = room_manager.get_room_key(room_id)
            if not room_key:
                emit('error', {'msg': 'Room key not available'})
                return
            
            # Save message to database FIRST
            msg_id = db.save_message(room_id, username, enc_msg, key_version, file_metadata)
            
            # Create message payload
            msg_payload = {
                'id': msg_id,
                'sender': username,
                'enc': enc_msg,
                'timestamp': datetime.datetime.now().timestamp(),
                'key_version': key_version,
                'file_metadata': file_metadata,
                'reactions': {}
            }
            
            logger.info(f"[MSG] {username} sent message in {room_id} (id: {msg_id}), broadcasting to room")
            
            # THE FIX: Use emit with 'to' parameter for room broadcasting
            # This broadcasts to ALL clients in the Socket.IO room
            emit('encrypted_msg', msg_payload, to=room_id, include_self=True, broadcast=True)
            
            logger.info(f"[MSG] ✓ Broadcasted message {msg_id} to all members in room {room_id}")
            
    except Exception as e:
        logger.error(f"[MSG] Error: {e}")
        import traceback
        traceback.print_exc()
        emit('error', {'msg': 'Failed to send message'})

@socketio.on('load_more_messages')
def handle_load_more(data):
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
            'file_metadata': msg['file_metadata']
        } for msg in messages]
    })

@socketio.on('upload_file')
def handle_file_upload(data):
    sid = request.sid
    if sid not in connections:
        emit('upload_error', {'msg': 'Not connected'})
        return
    
    try:
        # Decode the base64 file data
        file_data = base64.b64decode(data['file_data'])
        filename = secure_filename(data['filename'])
        content_type = data.get('content_type', 'application/octet-stream')
        
        # Check file size
        if len(file_data) > 16 * 1024 * 1024:
            emit('upload_error', {'msg': 'File too large (max 16MB)'})
            return
        
        # Check file type
        if not allowed_file(filename):
            emit('upload_error', {'msg': 'File type not allowed'})
            return
        
        # Generate unique file ID
        import secrets
        file_id = f"file_{secrets.token_hex(16)}"
        
        # Save file to uploads folder
        file_path = UPLOAD_FOLDER / f"{file_id}_{filename}"
        with open(file_path, 'wb') as f:
            f.write(file_data)
        
        emit('file_uploaded', {
            'file_id': file_id,
            'filename': filename,
            'size': len(file_data),
            'content_type': content_type
        })
        
        logger.info(f"[FILE] Saved {filename} ({len(file_data)} bytes) - ID: {file_id}")
    except Exception as e:
        logger.error(f"[FILE] Upload error: {e}")
        emit('upload_error', {'msg': f'File upload failed: {str(e)}'})

@socketio.on('delete_message')
def handle_delete_message(data):
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
    sid = request.sid
    if sid not in connections:
        return
    
    conn = connections[sid]
    room_id = conn['room_id']
    kicked_user = data.get('user', '')
    
    success, new_key, msg = room_manager.kick_user(room_id, conn['token'], kicked_user)
    
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
    
    # Remove from room_sids before distributing new key
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
    
    # Notify room AFTER removing kicked user - use 'to' parameter
    emit('sys_msg', {'type': 'kicked', 'user': kicked_user, 'msg': msg}, to=room_id, include_self=True, broadcast=True)
    
    # Distribute new key to remaining members
    threading.Thread(target=distribute_new_key_after_kick, 
                    args=(room_id, new_key, new_version), daemon=True).start()
    
    broadcast_room_update()
    broadcast_member_update(room_id)

@socketio.on('leave_room')
def handle_leave_room():
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
        
        logger.info(f"[LEAVE] {username} left {room_id}")

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    if sid in connections:
        username = connections[sid]['username']
        room_id = connections[sid].get('room_id')
        
        if username in active_sids:
            active_sids[username] = [s for s in active_sids[username] if s != sid]
            if not active_sids[username]:
                del active_sids[username]
        
        if room_id:
            if room_id in room_sids and sid in room_sids[room_id]:
                room_sids[room_id].remove(sid)
            emit('sys_msg', {'type': 'disconnected', 'user': username}, room=room_id, include_self=False)
            leave_room(room_id, sid)
        
        del connections[sid]
        logger.info(f"[DISCONNECT] {username}")

logger.info("="*60)
logger.info("🚀 STARTING SERVER - Fresh Instance")
logger.info(f"📊 Database: {db.DB_PATH}")
logger.info(f"🔑 Room keys in memory: {len(room_manager.room_keys) if hasattr(room_manager, 'room_keys') else 0}")
logger.info("="*60)

if __name__ == '__main__':
    host = config.get('host', 'localhost')
    port = config.get('port', 5000)
    socketio.run(app, host=host, port=port, debug=app.config['DEBUG'])