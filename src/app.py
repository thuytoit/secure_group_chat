import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
import json
import os
from users import register, login, is_admin, logout, load_users
from groups import GroupManager
from crypto import parameters, derive_key, encrypt_message
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_flask_key_change_this_later'
socketio = SocketIO(app, cors_allowed_origins="*")
gm = GroupManager()
clients = {}  # sid -> username
privates = {}  # sid -> private_key
user_keys = {}  # sid -> user_key bytes
backend = default_backend()

def get_username_from_token(token):
    users = load_users()
    for u, data in users.items():
        if data.get('token') == token:
            return u
    return None

def is_valid_user(token):
    return get_username_from_token(token) is not None

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
    if 'token' not in session:
        return redirect(url_for('index'))
    return render_template('chat.html', username=session['username'], role=session['role'])

@socketio.on('connect')
def handle_connect(auth):
    token = session.get('token')
    if not token or not is_valid_user(token):
        emit('error', {'msg': 'Invalid session'})
        return False
    username = get_username_from_token(token)
    success, _, _ = gm.add_user(username, token)
    clients[request.sid] = username
    join_room('group')
    # Manual DH private key generation (fallback for library issues)
    param_nums = parameters.parameter_numbers()
    p = param_nums.p
    g = param_nums.g
    key_size_bytes = (p.bit_length() + 7) // 8
    private_exponent = int.from_bytes(os.urandom(key_size_bytes), 'big') % (p - 2) + 2
    public_exponent = pow(g, private_exponent, p)
    public_numbers = dh.DHPublicNumbers(public_exponent, param_nums)
    private_numbers = dh.DHPrivateNumbers(private_exponent, public_numbers)
    private_key = private_numbers.private_key(backend)
    pub_key = private_key.public_key()
    pub_num = pub_key.public_numbers()
    length = (pub_num.y.bit_length() + 7) // 8
    pub_bytes = pub_num.y.to_bytes(length, 'big')
    emit('dh_pub', {'pub': pub_bytes.hex()})
    privates[request.sid] = private_key
    if success:
        emit('joined', {'msg': f"{username} joined the group!"}, room='group', skip_sid=request.sid)
        # Fallback: If this is the first user and no group key, generate one
        group = gm.groups.get('main_group', {})
        if not group.get('key'):
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from os import urandom
            group_key = urandom(32)  # 256-bit AES key
            gm.groups['main_group'] = {'key': group_key, 'members': []}  # Update in your groups.py logic if needed
            print("Generated initial group key")
    else:
        emit('reconnected', {'msg': f"{username} reconnected!"}, room='group', skip_sid=request.sid)

@socketio.on('dh_peer')
def handle_dh_peer(data):
    sid = request.sid
    if sid not in privates:
        return
    # Debug: log received pub
    pub_str = data.get('pub', '')
    print(f"Received client pub hex: {repr(pub_str[:50])}... (length: {len(pub_str)})")
    try:
        peer_pub_bytes = bytes.fromhex(pub_str)
    except ValueError as e:
        print(f"Invalid client pub hex: {e}")
        emit('error', {'msg': 'Invalid public key format'})
        return
    param_nums = parameters.parameter_numbers()
    p = param_nums.p
    try:
        peer_pub_int = int.from_bytes(peer_pub_bytes, 'big')
        if not (1 < peer_pub_int < p):
            print(f"Invalid peer pub value: {peer_pub_int} (must be 1 < y < p={p})")
            emit('error', {'msg': 'Invalid public key value'})
            return
        peer_pub_num = dh.DHPublicNumbers(peer_pub_int, param_nums)
        peer_pub_key = peer_pub_num.public_key(backend)
    except Exception as e:
        print(f"Error creating peer pub key: {e}")
        emit('error', {'msg': 'Failed to process public key'})
        return
    private = privates[sid]
    try:
        shared = private.exchange(peer_pub_key)
        print(f"Shared key derived successfully (length: {len(shared)})")
    except ValueError as e:
        print(f"DH exchange failed: {e}")
        emit('error', {'msg': 'Key exchange failed'})
        return
    user_key = derive_key(shared)
    user_keys[sid] = user_key
    # Send current group key encrypted for this user
    group = gm.groups['main_group']
    current_group_key = group.get('key')
    if current_group_key:
        enc = encrypt_message(current_group_key, user_key)
        emit('group_key', {'enc': enc.hex()})
        print(f"Sent encrypted group key to {sid}")
    else:
        print("No group key available yet")
    # Cleanup private
    del privates[sid]

@socketio.on('message')
def handle_message(data):
    token = session.get('token')
    if not token or not is_valid_user(token):
        return
    username = get_username_from_token(token)
    if request.sid not in clients or clients[request.sid] != username:
        return
    emit('encrypted_msg', {'enc': data['enc'], 'sender': username}, room='group', skip_sid=request.sid)

@socketio.on('admin_kick')
def handle_kick(data):
    token = session.get('token')
    if not is_admin(token):
        return
    kicked = data['user']
    success, new_key, msg = gm.kick_user(kicked, token)
    if success:
        # Kick client
        kicked_sid = None
        for s, u in list(clients.items()):
            if u == kicked:
                kicked_sid = s
                emit('kicked', {'msg': msg}, room=s)
                leave_room('group', s)
                if s in user_keys:
                    del user_keys[s]
                del clients[s]
                break
        emit('notice', {'msg': f"{msg}"}, room='group')
        # Send new group key to remaining
        for sid in list(clients.keys()):
            if sid in user_keys:
                ukey = user_keys[sid]
                enc = encrypt_message(new_key, ukey)
                emit('group_key', {'enc': enc.hex()}, room=sid)
    else:
        emit('error', {'msg': msg})

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    if sid in clients:
        username = clients[sid]
        emit('notice', {'msg': f"{username} disconnected"}, room='group')
        del clients[sid]
    if sid in privates:
        del privates[sid]
    if sid in user_keys:
        del user_keys[sid]
    leave_room('group', sid)

if __name__ == '__main__':
    socketio.run(app, host='localhost', port=5000, debug=True)