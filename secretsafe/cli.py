import getpass
import json
import os
import re
import subprocess

import argparse

from secretsafe import config
from secretsafe import data

CONFIG = config.Config()
STORE = data.store_from_config(CONFIG)


def _select_password(regex):
    names = STORE.list_passwords(regex=regex)
    if names and len(names) > 1:
        print('Select a secret:')
        for i in range(0, len(names)):
            print('{}. {}'.format(i + 1, names[i]))

        index = -1
        while index < 0 or len(names) < index:
            selection = raw_input('Secret index: ')

            if not selection.isdigit():
                print('Invalid selection.')
                continue

            index = int(selection)

            if 0 > index > len(names):
                print('Invalid selection.')
                continue
        return names[index - 1]
    elif names:
        return names[0]


def get(args):
    regex = None
    if args.name_pattern and not args.exact:
        regex = re.compile('.*{}.*'.format(' '.join(args.name_pattern)),
                           re.IGNORECASE)

    name = _select_password(regex)
    if not name:
        print('No matching passwords.')
        return

    raw_secret = STORE.get_password(name, getpass.getpass('Key Password: '))

    if args.echo:
        print(raw_secret)
    else:
        process = subprocess.Popen(['less', ], stdin=subprocess.PIPE)
        process.communicate('{}\n\n{}'.format(name, raw_secret))


def delete(args):
    regex = None
    if args.name_pattern:
        regex = re.compile('.*{}.*'.format(' '.join(args.name_pattern)))

    name = _select_password(regex)
    if not name:
        print('No matching passwords.')
        return

    confirm_delete = args.yes
    if not confirm_delete:
        user_input = ''
        print('Are you sure you want to delete: {}'.format(name))
        while user_input not in ['y', 'n']:
            user_input = raw_input('(Y/N): ').lower()
            if user_input not in ['y', 'n']:
                print('Invalid selection.')
            else:
                confirm_delete = user_input == 'y'

    if confirm_delete:
        STORE.delete_password(name)
    else:
        print('Cancelling deletion.')


def save(args):
    name = ''
    if args.name:
        name = ' '.join(args.name)
    else:
        while not name:
            name = raw_input('Secret Name: ')
            if not name:
                print('You must provide a name.')

    raw_secret = ''
    while not raw_secret:
        raw_secret = getpass.getpass('Secret: ')
        if not raw_secret:
            print('You must provide a secret.')

    key_password = ''
    while not key_password:
        key_password = getpass.getpass('Key Password: ')
        if not key_password:
            print('You must provide a secret key.')

    try:
        STORE.save_password(name, raw_secret, key_password,
                            overwrite=args.force)
    except data.PasswordExistsException:
        print('Password already exists, overwrite with --force.')


def load(args):
    filename = os.path.expanduser(args.filename)

    if not os.path.isfile(filename):
        print('{} is not a file.'.format(filename))
        return

    with open(filename, 'r') as fp:
        secrets = json.load(fp)

    key_password = ''
    while not key_password:
        key_password = getpass.getpass('Key Password: ')
        if not key_password:
            print('You must provide a secret key.')

    for name, raw_secret in secrets.items():
        print(name)
        STORE.save_password(name, bytes(raw_secret), key_password)


def export_to(args):
    exports = data.JsonFileDataStore().secret_export()
    data.store_from_config(CONFIG, store_name=args.store_name).secret_import(exports)


def main():
    parser = argparse.ArgumentParser('secretsafe')
    subparsers = parser.add_subparsers()

    get_parser = subparsers.add_parser('get')
    get_parser.set_defaults(func=get)
    get_parser.add_argument('name_pattern', nargs='*')
    get_parser.add_argument('-x', '--exact',
                            action='store_true', default=False)
    get_parser.add_argument('-e', '--echo',
                            action='store_true', default=False)

    save_parser = subparsers.add_parser('save')
    save_parser.set_defaults(func=save)
    save_parser.add_argument('name', nargs='*')
    save_parser.add_argument('-f', '--force',
                             action='store_true', default=False)

    delete_parser = subparsers.add_parser('delete')
    delete_parser.set_defaults(func=delete)
    delete_parser.add_argument('name_pattern', nargs='*')
    delete_parser.add_argument('-y', '--yes',
                               action='store_true', default=False)

    delete_parser = subparsers.add_parser('load')
    delete_parser.set_defaults(func=load)
    delete_parser.add_argument('filename')
    delete_parser.add_argument('-r', '--reuse',
                               action='store_true', default=False)

    delete_parser = subparsers.add_parser('export-to')
    delete_parser.set_defaults(func=export_to)
    delete_parser.add_argument('store_name', choices=data.STORES.keys())

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
