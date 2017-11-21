import base64
import json
import os

from google.api_core import exceptions as google_exceptions
from google.cloud import datastore

from secretsafe import crypto


class PasswordExistsException(Exception):
    pass


class PasswordMissingException(Exception):
    pass


class SecretExport(object):
    def __init__(self, name, b64salt, b64secret):
        self.name = name
        self.b64salt = b64salt
        self.b64secret = b64secret


class JsonFileDataStore(object):
    SECRETSAFE_STORE_NAME = 'json_file'

    DEFAULT_SECRET_FILE_PATH = '~/.secretsafe.json'

    def __init__(self, secret_file_path=DEFAULT_SECRET_FILE_PATH):
        self.secret_file_path = os.path.expanduser(secret_file_path)

    @classmethod
    def from_config(cls, config):
        secret_file_path = config.json_file_path
        if secret_file_path is None:
            secret_file_path = cls.DEFAULT_SECRET_FILE_PATH
        return cls(secret_file_path=secret_file_path)

    def save_password(self, name, raw_secret, key_password, overwrite=False):
        salt, enc_secret = crypto.encrypt(raw_secret, key_password)

        secret_file = {}
        if os.path.isfile(self.secret_file_path):
            with open(self.secret_file_path, 'r') as fp:
                secret_file = json.load(fp)

        if name in secret_file and not overwrite:
            raise PasswordExistsException()

        secret_file[name] = {'salt': base64.b64encode(salt),
                             'secret': base64.b64encode(enc_secret)}

        with open(self.secret_file_path, 'w') as fp:
            json.dump(secret_file, fp, indent=2)

    def get_password(self, name, key_password):
        secret_file = {}

        if os.path.isfile(self.secret_file_path):
            with open(self.secret_file_path, 'r') as fp:
                secret_file = json.load(fp)

        if name not in secret_file:
            raise PasswordMissingException()

        salt = base64.b64decode(secret_file[name]['salt'])
        enc_secret = base64.b64decode(secret_file[name]['secret'])

        return crypto.decrypt(enc_secret, salt, key_password)

    def list_passwords(self, regex=None):
        secret_file = {}

        if os.path.isfile(self.secret_file_path):
            with open(self.secret_file_path, 'r') as fp:
                secret_file = json.load(fp)

        names = secret_file.keys()

        if regex:
            names = [n for n in names if regex.match(n)]

        return names

    def delete_password(self, name):
        secret_file = {}

        if os.path.isfile(self.secret_file_path):
            with open(self.secret_file_path, 'r') as fp:
                secret_file = json.load(fp)

        if name in secret_file:
            del secret_file[name]
            with open(self.secret_file_path, 'w') as fp:
                json.dump(secret_file, fp, indent=2)

    def secret_export(self):
        exports = []
        with open(self.secret_file_path, 'r') as fp:
            secrets = json.load(fp)
            for name, secret in secrets.items():
                exports.append(SecretExport(name,
                                            secret['salt'],
                                            secret['secret']))
        return exports

    def secret_import(self, exports):
        secret_file = {}
        if os.path.isfile(self.secret_file_path):
            with open(self.secret_file_path, 'r') as fp:
                secret_file = json.load(fp)

        for export in exports:
            secret_file[export.name] = {'salt': export.b64salt,
                                        'secret': export.b64secret}

        with open(self.secret_file_path, 'w') as fp:
            json.dump(secret_file, fp, indent=2)


class GoogleCloudDataStore(object):
    SECRETSAFE_STORE_NAME = 'google_cloud'

    DS_KIND = 'Secret'
    DEFAULT_NAMESPACE = 'secretsafe'

    def __init__(self, project, namespace=DEFAULT_NAMESPACE):
        self.client = datastore.Client(project=project, namespace=namespace)

    @classmethod
    def from_config(cls, config):
        namespace = config.google_namespace
        if namespace is None:
            namespace = cls.DEFAULT_NAMESPACE
        return cls(config.google_project, namespace=namespace)

    def save_password(self, name, raw_secret, key_password, overwrite=False):
        ds_key = self.client.key(self.DS_KIND, name)
        ds_secret = self.client.get(ds_key)
        if ds_secret is None:
            ds_secret = datastore.Entity(ds_key)
        elif ds_secret is not None and not overwrite:
            raise PasswordExistsException()

        cipher_text, salt = crypto.encrypt(raw_secret, key_password)
        ds_secret['salt'] = base64.b64encode(salt)
        ds_secret['secret'] = base64.b64encode(cipher_text)

        self.client.put(ds_secret)

    def get_password(self, name, key_password):
        ds_key = self.client.key(self.DS_KIND, name)
        ds_secret = self.client.get(ds_key)
        if ds_secret is None:
            raise PasswordMissingException()

        salt = base64.b64decode(ds_secret['salt'])
        cipher_text = base64.b64decode(ds_secret['secret'])
        return crypto.decrypt(cipher_text, salt, key_password)

    def list_passwords(self, regex=None):
        query = self.client.query(kind=self.DS_KIND)

        names = []
        for ds_secret in query.fetch():
            names.append(ds_secret.key.name)

        if regex:
            names = [n for n in names if regex.match(n)]

        return names

    def delete_password(self, name):
        ds_key = self.client.key(self.DS_KIND, name)
        try:
            self.client.delete(ds_key)
        except google_exceptions.NotFound:
            pass

    def secret_export(self):
        query = self.client.query(kind=self.DS_KIND)
        exports = []
        for ds_secret in query.fetch():
            exports.append(SecretExport(ds_secret.key.name,
                                        ds_secret['salt'],
                                        ds_secret['secret']))
        return exports

    def secret_import(self, exports):
        for export in exports:
            ds_key = self.client.key(self.DS_KIND, export.name)
            ds_entity = datastore.Entity(ds_key)
            ds_entity['salt'] = export.b64salt
            ds_entity['secret'] = export.b64secret
            self.client.put(ds_entity)


STORES = {store.SECRETSAFE_STORE_NAME: store
          for store in [JsonFileDataStore, GoogleCloudDataStore]}


def store_from_config(config, store_name=None):
    if store_name:
        return STORES[store_name].from_config(config)
    return STORES[config.datastore].from_config(config)
