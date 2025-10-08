import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

config_path = os.path.join(os.path.dirname(__file__), 'config.json')
with open(config_path, 'r') as f:
    config = json.load(f)

backend = default_backend()
parameters = dh.generate_parameters(generator=2, key_size=config['key_size'])

def derive_key(shared_secret, salt=None):
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

def ratchet_key(current_key):
    try:
        with open('key_version.txt', 'r') as f:
            version = int(f.read()) + 1
    except FileNotFoundError:
        version = 1
    with open('key_version.txt', 'w') as f:
        f.write(str(version))
    return hashlib.sha256(current_key + str(version).encode()).digest()

def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(message.encode()) + padder.finalize()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return iv + encrypted

def decrypt_message(encrypted_data, key):
    iv = encrypted_data[:16]
    encrypted = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode()