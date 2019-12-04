import os

from six.moves import configparser

DEFAULT_CONFIG_PATH = '~/.secretsaferc'


class Config(object):
    _configs = [
        ('datastore', 'SECRETSAFE_DATASTORE'),

        ('json_file_path', 'SECRETSAFE_JSON_FILE_PATH'),

        ('google_project', 'SECRETSAFE_GOOGLE_PROJECT'),
        ('google_namespace', 'SECRETSAFE_GOOGLE_NAMESPACE'),
    ]

    def __init__(self, config_path=DEFAULT_CONFIG_PATH):
        for name, env in self._configs:
            setattr(self, name, os.environ.get(env))

        config_path = os.path.expanduser(config_path)
        if os.path.isfile(config_path):
            parser = configparser.ConfigParser()
            with open(config_path, 'r') as fp:
                parser.readfp(fp)
            for name, env in self._configs:
                if parser.has_option('DEFAULT', name) and getattr(self, name) is None:
                    setattr(self, name, parser.get('DEFAULT', name))
