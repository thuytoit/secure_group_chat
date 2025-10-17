import sys
import os
import json
import hashlib
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# Load config
CONFIG_PATH = Path(__file__).parent / 'config.json'
with open(CONFIG_PATH, 'r') as f:
    config = json.load(f)

backend = default_backend()

p = int('B6F676C1440DBDAF286A55D9CC2826E67355B077EB15D49D93981E685852282B1A5F15B9C4FD15C0A17A234DC414B46868A785CDDB55DA662DD64BFAF7E32D33D28273DA1CEBAC9CF2BD720E492FCF01AD3AC4A2B04843FA7DDF8279C7459F7AC078E87282D7B417D478466809EE2981E32681A792F6C2454FA62DA4CB2498C7', 16)
g = 2
parameters = dh.DHParameterNumbers(p, g).parameters(backend)

def derive_key(shared_secret: bytes, salt: bytes | None = None) -> bytes:
    if salt is None:
        salt = config['salt'].encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=config['iterations'],
        backend=backend
    )
    return kdf.derive(shared_secret)

def ratchet_key(current_key: bytes, version: int | None = None) -> bytes:
    """
    Deterministic key ratcheting using HKDF-style derivation.
    Efficient (single SHA256), secure (domain sep + version).
    """
    if version is None:
        version = 1
    
    h = hashlib.sha256()
    h.update(b'ratchet_v1')  # Domain separator
    h.update(current_key)
    h.update(str(version).encode())
    return h.digest()

def encrypt_message(message: bytes | str, key: bytes) -> bytes:
    """AES-256-CBC encrypt (fast for small msgs)."""
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded = padder.update(message) + padder.finalize()
    
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return iv + encrypted