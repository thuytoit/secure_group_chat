# Secure Multi-Room Chat — Browser-Based E2EE Group Messaging

A web-based group chat application where all cryptographic operations occur exclusively in the browser. The server stores only ciphertext and never holds or derives encryption keys, making it architecturally incapable of reading message content.

Built as a Bachelor's thesis project at International University — Vietnam National University HCMC.

---

## Demo

**Main Features Demo**

[![Main Features Demo](https://img.youtube.com/vi/XzBxMwm1Nhg/hqdefault.jpg)](https://youtu.be/XzBxMwm1Nhg?si=yGm-R0IO9qP6YXbv)

**Additional Features Demo**

[![Additional Features Demo](https://img.youtube.com/vi/DzQl8hLjbBY/hqdefault.jpg)](https://youtu.be/DzQl8hLjbBY?si=nqyDo8OK02-x11o8)

---

## How It Works

When a user sends a message:

1. A random 16-byte IV is generated in the browser
2. The message is encrypted with AES-256-CBC using the room's group key
3. The IV is prepended to the ciphertext and hex-encoded
4. Only the encrypted hex string reaches the server and database

Group keys never leave the browser. When a new member joins, keys are shared peer-to-peer using Diffie-Hellman key exchange (RFC 3526 2048-bit MODP prime) with PBKDF2-SHA256 key derivation — the server only relays encrypted blobs between clients.

When a user is kicked, the admin's browser generates a new random group key and distributes it to remaining members via the same P2P mechanism. The removed user cannot decrypt anything sent after their removal.

---

## Features

**Core encryption**
- AES-256-CBC message encryption with random IV per message
- Diffie-Hellman peer-to-peer group key distribution (RFC 3526 2048-bit MODP prime)
- PBKDF2-SHA256 key derivation at 100,000 iterations
- Client-side key rotation triggered on user removal
- Keys persisted in browser localStorage across page refreshes
- Client-side encrypted file attachments

**Rooms**
- Public rooms: discoverable and joinable from the hub
- Private rooms: invite-code only with optional password protection
- Admin controls: edit room, switch public/private, kick user, delete room
- Admin succession transfers automatically to longest-standing member on owner departure

**Real-time**
- WebSocket messaging via Flask-SocketIO
- Typing indicators
- Online presence status per room
- Message reactions with real-time sync across all clients

**Moderation**
- Kick user with automatic client-side key rotation
- Soft message deletion by sender, room admin, or global admin
- Report system with mandatory image evidence
- Global admin moderation panel with room snapshots and risk scoring

**User data control (GDPR)**
- Data export: server returns encrypted data, browser decrypts locally, plaintext JSON downloads automatically
- Account deletion: permanently removes all messages, reactions, memberships, uploaded files, and evidence images

**Interface**
- Dark mode with localStorage persistence
- Persistent encrypted message history with pagination
- Multiple file attachments per message

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask, Flask-SocketIO |
| Database | SQLite with Write-Ahead Logging (WAL) mode |
| Cryptography | CryptoJS (AES-256-CBC, PBKDF2), Web Crypto API (secure random), custom DH modular exponentiation |
| Real-time | WebSocket via Socket.IO |
| Frontend | HTML, CSS, Vanilla JavaScript |
| Authentication | bcrypt password hashing, custom stateful session tokens |

---

## Installation

**Requirements:** Python 3.8 or higher

```bash
# 1. Navigate to the project root
cd GroupChatProject

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the server
cd src
python app.py

# 4. Open in browser
# http://localhost:5000
```

Default admin account: `admin` / `adminpass`

The database (`src/chat.db`), user accounts file (`users.json`), and uploads folder are created automatically on first run. No manual setup required.

Copy src/config.example.json and rename it to src/config.json; then edit src/config.json to set secret_key to a long random secret and salt to a unique string.

---

## Project Structure

```
GroupChatProject/
├── requirements.txt
└── src/
    ├── app.py            Flask routes and all Socket.IO event handlers
    ├── database.py       SQLite read and write operations
    ├── rooms.py          Room lifecycle and key version management
    ├── users.py          User authentication and account management
    ├── crypto.py         Diffie-Hellman parameters (RFC 3526 2048-bit MODP prime)
    ├── config.json       Server configuration (host, port, salt, iterations)
    ├── static/
    │   └── css/          Stylesheets (chat, hub, dark mode)
    └── templates/
        ├── index.html    Login and registration page
        ├── hub.html      Room selection hub
        └── chat.html     Chat interface — all client-side cryptographic logic lives here
```

---

## Security Design Notes

- The server never receives plaintext group keys — only encrypted blobs relayed between peer browsers
- Message content is verifiable as ciphertext only by inspecting the `encrypted_content` column in `src/chat.db`
- Encryption keys exist only in users' browsers under `localStorage` keys named `room_{ROOM_ID}_keys`

**Acknowledged limitations (documented in thesis)**
- localStorage dependency: clearing browser data loses access to old message history
- CBC mode without authentication tag: GCM would be the correct production choice
- No prekey system: at least one existing room member must be online to share the key with a new joiner
- No perfect forward secrecy: key rotation occurs only on kick, not on every message