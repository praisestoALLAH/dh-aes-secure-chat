"""AES encryption helpers (uses the 'cryptography' library for AES only)."""
import hashlib
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_aes_key(shared_secret_bytes):
    """The DH shared secret is a huge number, but AES-256 needs exactly 32 bytes.
    Hashing it with SHA-256 gives a 32-byte key."""
    return hashlib.sha256(shared_secret_bytes).digest()


def encrypt(key, plaintext):
    """AES-256-GCM encryption.
    GCM needs a unique 12-byte nonce for every message, so we generate a random
    one and put it in front of the ciphertext. GCM also adds an authentication
    tag, so any modification of the data is detected when decrypting."""
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def decrypt(key, data):
    """Split nonce and ciphertext, then decrypt. Raises an error if tampered."""
    nonce, ciphertext = data[:12], data[12:]
    return AESGCM(key).decrypt(nonce, ciphertext, None)
