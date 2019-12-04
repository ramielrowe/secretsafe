#!/usr/bin/env python

from setuptools import setup

description = "Secret Management"

setup(
    name="secretsafe",
    version='0.0.1',
    author="Andrew Melton",
    author_email="andrew@apmelton.com",
    description=description,
    long_description=description,
    license="Apache",
    keywords="secret password management",
    url="https://github.com/ramielrowe/secretsafe",
    packages=['secretsafe'],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
    ],
    setup_requires=(
        'cryptography',
        'six',
    ),
    install_requires=(
        'cryptography',
        'six',
    ),
    entry_points={
        'console_scripts': ['secretsafe=secretsafe.cli:main'],
    }

)
