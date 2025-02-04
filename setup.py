#!/usr/bin/env python

import os
import re
import runpy
import subprocess
import sys
from pathlib import Path

import pybind11
from setuptools import Extension, find_namespace_packages, setup
from setuptools.command.build_ext import build_ext


def get_version():
    run_globals = runpy.run_path(Path(__file__).parent / 'replicat/__version__.py')
    return run_globals['version']


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
    version=get_version(),
    url='https://github.com/vaultah/replicat',
    project_urls={
        'Source': 'https://github.com/vaultah/replicat',
    },
    maintainer='vaultah',
    maintainer_email='flwaultah+replicat@gmail.com',
    python_requires='>=3.8',
    description='Configurable and lightweight backup utility with '
    'deduplication and encryption.',
    long_description=get_long_description(),
    long_description_content_type='text/markdown',
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX",
        "Operating System :: POSIX :: BSD",
        "Operating System :: POSIX :: Linux",
        'Operating System :: Microsoft :: Windows',
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: System :: Archiving :: Backup",
        "License :: OSI Approved :: MIT License",
    ],
    packages=find_namespace_packages(include=['replicat', 'replicat.*']),
    install_requires=[
        'httpx>=0.22,<1',
        'cryptography>=35',
        'backoff>=2,<3',
        'platformdirs>=4.3.6,<4.4',
        'tqdm>=4.63,<5',
        'sty>=1,<1.1',
        'tomli >= 1.1.0 ; python_version < "3.11"',
    ],
    extras_require=extras_require,
    ext_modules=[CMakeExtension('_replicat_adapters')],
    cmdclass={'build_ext': CMakeBuild},
    entry_points={
        'console_scripts': ['replicat = replicat.__main__:main'],
    },
)
