import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
import json
from users import register, login, is_admin, logout, load_users
from groups import GroupManager
from crypto import parameters, derive_key, encrypt_message, decrypt_message
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_flask_key_change_this_later'
socketio = SocketIO(app, cors_allowed_origins="*")
gm = GroupManager()
group_key = None
clients = {}  # sid -> username
privates = {}  # sid -> private_key
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
def handle_connect():
    token = session.get('token')
    if not token or not is_valid_user(token):
        emit('error', {'msg': 'Invalid session'})
        return False
    username = get_username_from_token(token)
    clients[request.sid] = username
    join_room('group')
    # DH: Generate private/pub
    private_key = parameters.generate_private_key()
    pub_num = private_key.public_key().public_numbers()
    pub_bytes = pub_num.y.to_bytes((pub_num.y.bit_length() + 7) // 8, 'big')
    emit('dh_pub', {'pub': pub_bytes.hex()})
    privates[request.sid] = private_key
    success, current_key, _ = gm.add_user(username, token)
    if current_key:
        global group_key
        group_key = current_key
    emit('joined', {'msg': f"{username} joined!"})

@socketio.on('dh_peer')
def handle_dh_peer(data):
    sid = request.sid
    if sid not in privates:
        return
    private = privates[sid]
    peer_pub_bytes = bytes.fromhex(data['pub'])
    peer_pub_num = dh.DHPublicNumbers(int.from_bytes(peer_pub_bytes, 'big'), parameters)
    peer_pub_key = peer_pub_num.public_key(backend)
    shared = private.exchange(peer_pub_key)
    user_key = derive_key(shared)
    # Encrypt group_key for this user
    if group_key:
        enc = encrypt_message(group_key, user_key)
        emit('group_key', {'enc': enc.hex()})

@socketio.on('message')
def handle_message(data):
    token = session.get('token')
    if not token or not group_key:
        return
    username = get_username_from_token(token)
    enc = encrypt_message(data['msg'], group_key)
    emit('encrypted_msg', {'enc': enc.hex(), 'sender': username}, room='group')

@socketio.on('admin_kick')
def handle_kick(data):
    token = session.get('token')
    if not is_admin(token):
        return
    kicked = data['user']
    success, new_key, msg = gm.kick_user(kicked, token)
    if success:
        global group_key
        group_key = new_key
        emit('notice', {'msg': f"Kicked {kicked}. Key rotated!"}, room='group')
        # Kick client
        for s, u in list(clients.items()):
            if u == kicked:
                emit('kicked', {'msg': 'Kicked!'}, room=s)
                leave_room('group', s)
                del clients[s]

if __name__ == '__main__':
    socketio.run(app, host='localhost', port=5000, debug=True)