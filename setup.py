#!/usr/bin/env python

import os
import re
import subprocess
import sys
from pathlib import Path

import pybind11
from setuptools import Extension, find_namespace_packages, setup
from setuptools.command.build_ext import build_ext


def get_long_description():
    return Path('README.md').read_text('utf-8')


# Taken from https://github.com/pybind/cmake_example/blob/master/setup.py
# with modification
class CMakeExtension(Extension):
    def __init__(self, name, sourcedir=""):
        super().__init__(name, sources=[])
        self.sourcedir = os.path.abspath(sourcedir)


class CMakeBuild(build_ext):
    def build_extension(self, ext):
        build_temp = Path(self.build_temp).resolve()
        build_temp.mkdir(parents=True, exist_ok=True)

        extdir = Path(self.get_ext_fullpath(ext.name)).resolve().parent
        extdir.mkdir(parents=True, exist_ok=True)

        config = 'Debug' if self.debug else 'Release'
        cmake_args = [
            '-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=' + str(extdir.resolve()),
            '-DCMAKE_BUILD_TYPE=' + config,
            '-DPYTHON_EXECUTABLE=' + sys.executable,
            '-Dpybind11_DIR=' + pybind11.get_cmake_dir(),
        ]
        build_args = []

        if sys.platform.startswith("darwin"):
            # Cross-compile support for macOS - respect ARCHFLAGS if set
            archs = re.findall(r"-arch (\S+)", os.environ.get("ARCHFLAGS", ""))
            if archs:
                cmake_args += ["-DCMAKE_OSX_ARCHITECTURES={}".format(";".join(archs))]

        if self.compiler.compiler_type == 'msvc':
            cmake_args += [
                f'-DCMAKE_LIBRARY_OUTPUT_DIRECTORY_{config.upper()}={extdir}'
            ]
            build_args += ['--config', config]

        # Set CMAKE_BUILD_PARALLEL_LEVEL to control the parallel build level
        # across all generators.
        if 'CMAKE_BUILD_PARALLEL_LEVEL' not in os.environ:
            # self.parallel is a Python 3 only way to set parallel jobs by hand
            # using -j in the build_ext call, not supported by pip or PyPA-build.
            if hasattr(self, 'parallel') and self.parallel:
                # CMake 3.12+ only.
                build_args += [f'-j{self.parallel}']

        subprocess.check_call(
            ['cmake', ext.sourcedir] + cmake_args, cwd=self.build_temp
        )
        subprocess.check_call(
            ['cmake', '--build', '.'] + build_args, cwd=self.build_temp
        )


extras_require = {'test': ['pytest', 'pytest-asyncio<0.17']}
extras_require['all'] = [y for x in extras_require.values() for y in x]

setup(
    name='replicat',
    version='1.1.1',
    url="https://github.com/vaultah/replicat",
    maintainer='vaultah',
    maintainer_email='flwaultah+replicat@gmail.com',
    python_requires=">=3.9",
    description='Configurable and lightweight backup utility with '
    'deduplication and encryption.',
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    packages=find_namespace_packages(include=['replicat', 'replicat.*']),
    install_requires=[
        'httpx',
        'cryptography',
        'backoff',
        'appdirs',
        'tqdm',
        'sty',
    ],
    extras_require=extras_require,
    ext_modules=[CMakeExtension('_replicat_adapters')],
    cmdclass={'build_ext': CMakeBuild},
    entry_points={
        'console_scripts': ['replicat = replicat.__main__:main'],
    },
)
