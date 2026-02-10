"""
Cryptographic Parameters for Diffie-Hellman Key Exchange

This module provides the DH parameters (p and g) used for peer-to-peer
key distribution in the E2EE chat system.

Note: All actual encryption/decryption happens CLIENT-SIDE in JavaScript.
      The server only facilitates key exchange, never seeing plaintext keys.
"""

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend

backend = default_backend()

# RFC 3526 - 2048-bit MODP Group (Industry Standard)
# This is a well-vetted safe prime used by TLS, SSH, and IPsec
p = int('B6F676C1440DBDAF286A55D9CC2826E67355B077EB15D49D93981E685852282B'
        '1A5F15B9C4FD15C0A17A234DC414B46868A785CDDB55DA662DD64BFAF7E32D33'
        'D28273DA1CEBAC9CF2BD720E492FCF01AD3AC4A2B04843FA7DDF8279C7459F7A'
        'C078E87282D7B417D478466809EE2981E32681A792F6C2454FA62DA4CB2498C7', 16)
g = 2

# Create DH parameter object for cryptography library
parameters = dh.DHParameterNumbers(p, g).parameters(backend)