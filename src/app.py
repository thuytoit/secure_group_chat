import sys
import os
import json
import logging
import datetime  # For timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from users import register, login, is_admin, logout, load_users
from groups import GroupManager
from crypto import parameters, derive_key, encrypt_message
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend

# Load config
CONFIG_PATH = Path(__file__).parent / 'config.json'
with open(CONFIG_PATH, 'r') as f:
    config = json.load(f)

app = Flask(__name__)
app.config['SECRET_KEY'] = config['secret_key']
app.config['DEBUG'] = config.get('flask_debug', False)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')  # Efficient async for small scale
gm = GroupManager()

# Logging setup (pro: structured, levels)
logging.basicConfig(level=logging.INFO if app.config['DEBUG'] else logging.WARNING)
logger = logging.getLogger(__name__)

# Connection tracking
connections = {}
active_sids = {}  # username -> list[sids]
backend = default_backend()

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
    return jsonify({'success': success, 'token': token, 'role': role, 'msg': 'Logged in' if success else 'Fail'})

@app.route('/logout')
def do_logout():
    token = session.get('token')
    if token:
        logout(token)
    session.clear()
    return redirect(url_for('index'))

@app.route('/chat')
def chat():
    redirect_to = require_auth()
    if redirect_to:
        return redirect_to
    return render_template('chat.html', 
                          username=session['username'], 
                          role=session['role'], 
                          token=session['token'],
                          salt=config['salt'],  # Pass to JS for match
                          iterations=config['iterations'],
                          now=datetime.datetime.now(datetime.timezone.utc).isoformat())  # Cache buster, no deprecation/zoneinfo error

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'users': len(load_users())})

@socketio.on('connect')
def handle_connect(auth):
    token = auth.get('token')
    if not token or not is_valid_user(token):
        emit('error', {'msg': 'Invalid session'})
        return False

    username = get_username_from_token(token)
    sid = request.sid

    # Enforce single session (efficient: O(1) disconnect old)
    if username in active_sids:
        for old_sid in active_sids[username][:]:  # Copy to avoid mod during iter
            emit('force_disconnect', room=old_sid)
            if old_sid in connections:
                del connections[old_sid]
    active_sids[username] = [sid]

    connections[sid] = {
        'username': username,
        'token': token,
        'user_key': None,
        'priv_key': None
    }

    join_room('group')
    logger.info(f"[CONNECT] {username} ({sid})")

    # DH keypair gen (fast, per-connect)
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
    emit('dh_pub', {'pub': pub_bytes.hex()})
    logger.info(f"[DH] Public key sent to {sid}")

@socketio.on('dh_peer')
def handle_dh_peer(data):
    sid = request.sid
    if sid not in connections:
        emit('error', {'msg': 'Session lost'})
        return

    try:
        priv_key = connections[sid]['priv_key']
        if not priv_key:
            raise ValueError('Key exchange failed')

        pub_hex = data.get('pub', '')
        peer_pub_bytes = bytes.fromhex(pub_hex)
        param_nums = parameters.parameter_numbers()
        p = param_nums.p
        peer_pub_int = int.from_bytes(peer_pub_bytes, 'big')

        if not (1 < peer_pub_int < p):
            raise ValueError('Invalid public key')

        peer_pub_num = dh.DHPublicNumbers(peer_pub_int, param_nums)
        peer_pub_key = peer_pub_num.public_key(backend)

        shared = priv_key.exchange(peer_pub_key)
        user_key = derive_key(shared)
        connections[sid]['user_key'] = user_key
        logger.info(f"[DH] Exchange complete for {sid}")
    except Exception as e:
        logger.error(f"[DH] Failed for {sid}: {e}")
        emit('error', {'msg': 'Key exchange failed'})
        return

    # Send group key (encrypted per-user)
    group = gm.groups.get('main_group', {})
    group_key = group.get('key')
    version = group.get('version', 0)

    if group_key:
        enc_data = encrypt_message(group_key, user_key)
        emit('group_key', {'enc': enc_data.hex(), 'version': version, 'status': 'initial'})
        logger.info(f"[KEY] Sent v{version} to {sid}")

    # Add/notify
    username = connections[sid]['username']
    success, _, _ = gm.add_user(username, connections[sid]['token'])
    emit('sys_msg', {'type': 'joined', 'user': username}, room='group', skip_sid=sid)
    logger.info(f"[SYS] {username} joined")

    connections[sid]['priv_key'] = None  # Cleanup (mem efficient)

@socketio.on('message')
def handle_message(data):
    sid = request.sid
    if sid not in connections or connections[sid]['user_key'] is None:
        emit('error', {'msg': 'Key not ready'})
        return

    conn = connections[sid]
    if not is_valid_user(conn['token']):
        emit('error', {'msg': 'Session expired'})
        return

    username = conn['username']
    enc_msg = data.get('enc', '')

    # Broadcast (O(1) via room)
    emit('encrypted_msg', {'sender': username, 'enc': enc_msg}, room='group', skip_sid=sid)
    logger.info(f"[MSG] {username}")

@socketio.on('admin_kick')
def handle_kick(data):
    sid = request.sid
    if sid not in connections:
        return

    conn = connections[sid]
    if not is_admin(conn['token']):
        emit('error', {'msg': 'Not authorized'})
        return

    kicked_user = data.get('user', '')
    success, new_key, msg = gm.kick_user(kicked_user, conn['token'])

    if not success:
        emit('error', {'msg': msg})
        return

    logger.info(f"[KICK] {kicked_user} kicked")
    new_version = gm.groups['main_group'].get('version', 0)

    # Disconnect all for kicked (efficient loop)
    if kicked_user in active_sids:
        for s in active_sids[kicked_user][:]:
            emit('kicked', {'msg': msg}, room=s)
            leave_room('group', s)
            if s in connections:
                del connections[s]
        active_sids[kicked_user] = []

    emit('sys_msg', {'type': 'kicked', 'user': kicked_user, 'msg': msg}, room='group')

    # Rotate & broadcast to remaining (O(n), but n small)
    for s in list(connections):
        if connections[s]['user_key'] is not None:
            enc_data = encrypt_message(new_key, connections[s]['user_key'])
            emit('group_key', {'enc': enc_data.hex(), 'version': new_version, 'status': 'rotated'}, room=s)

    logger.info(f"[KEY] Rotated to v{new_version}, sent to {len(connections)} users")

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    if sid in connections:
        username = connections[sid]['username']
        if username in active_sids:
            active_sids[username].remove(sid)
            if not active_sids[username]:
                del active_sids[username]
        del connections[sid]
        emit('sys_msg', {'type': 'disconnected', 'user': username}, room='group')
        logger.info(f"[DISCONNECT] {username}")

    leave_room('group', sid)

if __name__ == '__main__':
    host = config.get('host', 'localhost')
    port = config.get('port', 5000)
    socketio.run(app, host=host, port=port, debug=app.config['DEBUG'])