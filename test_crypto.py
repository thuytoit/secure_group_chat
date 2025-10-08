import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.crypto import derive_key, ratchet_key, encrypt_message, decrypt_message

# Test derive (uses 32-byte key from PBKDF2)
print("Derive test:", derive_key(b"shared_secret")[:10])  # First 10 bytes

# Test ratchet (start with proper 32-byte key)
key = os.urandom(32)  # Random 32 bytes for AES
new_key = ratchet_key(key)
print("Ratchet test: New key != old?", new_key != key)  # True

# Test encrypt/decrypt (uses the original 32-byte key)
msg = "Secret test!"
enc = encrypt_message(msg, key)
dec = decrypt_message(enc, key)
print("E2EE test:", dec == msg)  # True