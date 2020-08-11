#!/usr/bin/env python

from setuptools import find_packages, setup

extras_require = {
    'test': [
        'pytest',
        'pytest-asyncio'
    ],
    'progress': [
        'tqdm'
    ]
}

extras_require['all'] = [y for x in extras_require.values() for y in x]

setup(
    name='replicat',
    version='0.0.1',
    python_requires=">=3.7",
    description='Configurable and lightweight backup utility with '
                'deduplication, encryption and stuff.',
    packages=find_packages(),
    install_requires=[
        'httpx@git+https://github.com/encode/httpx.git@master',
        'cryptography',
    ],
    extras_require=extras_require,
)
