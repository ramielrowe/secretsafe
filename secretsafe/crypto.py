import base64
import os

from cryptography import fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf import pbkdf2
from cryptography.hazmat import backends

DEFAULT_KEY_LENGTH=32
DEFAULT_KEY_ITERATIONS=100000


def decrypt(cipher_text, salt, key_phrase,
            key_length=DEFAULT_KEY_LENGTH, key_iterations=DEFAULT_KEY_ITERATIONS):
    backend = backends.default_backend()
    kdf = pbkdf2.PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=key_iterations,
        backend=backend
    )
    key = base64.b64encode(kdf.derive(key_phrase.encode()))
    return fernet.Fernet(key).decrypt(cipher_text)


def encrypt(plaint_text, key_phrase,
            key_length=DEFAULT_KEY_LENGTH, key_iterations=DEFAULT_KEY_ITERATIONS):
    salt = os.urandom(16)
    backend = backends.default_backend()
    kdf = pbkdf2.PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=key_iterations,
        backend=backend
    )
    key = base64.b64encode(kdf.derive(key_phrase.encode()))
    cipher_text = fernet.Fernet(key).encrypt(plaint_text)
    return cipher_text, salt