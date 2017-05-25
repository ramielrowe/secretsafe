import base64
import json
import os

from cryptography import fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf import pbkdf2
from cryptography.hazmat import backends

SECRET_FILE_PATH = os.path.expanduser('~/.secretsafe.json')


class PasswordExistsException(Exception):
    pass


class PasswordMissingException(Exception):
    pass


def save_password(name, raw_secret, key_password, overwrite=False):
    salt = os.urandom(16)
    backend = backends.default_backend()
    kdf = pbkdf2.PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = base64.urlsafe_b64encode(kdf.derive(key_password))
    enc_secret = fernet.Fernet(key).encrypt(raw_secret)

    secret_file = {}
    if os.path.isfile(SECRET_FILE_PATH):
        with open(SECRET_FILE_PATH, 'r') as fp:
            secret_file = json.load(fp)

    if name in secret_file and not overwrite:
        raise PasswordExistsException()

    secret_file[name] = {'salt': base64.b64encode(salt),
                         'secret': base64.b64encode(enc_secret)}

    with open(SECRET_FILE_PATH, 'w') as fp:
        json.dump(secret_file, fp, indent=2)


def get_password(name, key_password):
    secret_file = {}

    if os.path.isfile(SECRET_FILE_PATH):
        with open(SECRET_FILE_PATH, 'r') as fp:
            secret_file = json.load(fp)

    if name not in secret_file:
        raise PasswordMissingException()

    salt = base64.b64decode(secret_file[name]['salt'])
    enc_secret = base64.b64decode(secret_file[name]['secret'])

    backend = backends.default_backend()
    kdf = pbkdf2.PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )

    key = base64.b64encode(kdf.derive(key_password))
    return fernet.Fernet(key).decrypt(enc_secret)


def list_passwords(regex=None):
    secret_file = {}

    if os.path.isfile(SECRET_FILE_PATH):
        with open(SECRET_FILE_PATH, 'r') as fp:
            secret_file = json.load(fp)

    names = secret_file.keys()

    if regex:
        names = [n for n in names if regex.match(n)]

    return names


def delete_password(name):
    secret_file = {}

    if os.path.isfile(SECRET_FILE_PATH):
        with open(SECRET_FILE_PATH, 'r') as fp:
            secret_file = json.load(fp)

    if name in secret_file:
        del secret_file[name]
        with open(SECRET_FILE_PATH, 'w') as fp:
            json.dump(secret_file, fp, indent=2)
