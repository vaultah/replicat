#!/usr/bin/env python

from setuptools import find_packages, setup

setup(
    name='replicat',
    version='0.0.1',
    python_requires=">=3.7",
    description='Configurable and lightweight backup utility with '
                'deduplication, encryption and stuff.',
    packages=find_packages(),
    install_requires=[
        'aiohttp', # TODO: switch to httpx
        'cryptography',
    ],
    extras_require={
        'test': [
            'pytest',
            'pytest-asyncio'
        ],
    },
)
