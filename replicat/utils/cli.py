import argparse
import inspect
import logging
import os
from pathlib import Path

from . import (
    FileListColumn,
    SnapshotListColumn,
    __version__,
    backend_env_var,
    config,
    guess_type,
    human_to_bytes,
    parse_repository,
)

logger = logging.getLogger(__name__)


def _read_bytes(path):
    return Path(path).read_bytes()


initial_parser = argparse.ArgumentParser(add_help=False)
initial_parser.add_argument(
    '-r',
    '--repository',
    type=parse_repository,
    help='<backend>:<connection string>. The REPLICAT_REPOSITORY environment '
    "variable is used as a fallback. If neither is provided, we'll use the CWD.",
)
initial_parser.add_argument(
    '--profile',
    help='Use settings from this profile in the configuration file '
    '(default options are always applied)',
)
config_group = initial_parser.add_mutually_exclusive_group()
config_group.add_argument(
    '--ignore-config',
    help='Ignore configuration file',
    action='store_const',
    dest='configuration_file',
    const=None,
    default=argparse.SUPPRESS,
)
config_group.add_argument(
    '--config',
    help=f'Path to the configuration file (default is {config.DEFAULT_CONFIG_PATH})',
    dest='configuration_file',
    type=Path,
    default=config.DEFAULT_CONFIG_PATH,
)
initial_parser.add_argument('-v', '--verbose', action='count', default=0)

common_options_parser = argparse.ArgumentParser(add_help=False)
common_options_parser.add_argument(
    '-q',
    '--hide-progress',
    dest='quiet',
    action='store_true',
    help='Disable progress bar for commands that support it.',
)
common_options_parser.add_argument(
    '-c',
    '--concurrent',
    type=int,
    help='The number of concurrent connections to the backend '
    f'(the default is {config.DEFAULT_CONCURRENT}).',
    default=config.DEFAULT_CONCURRENT,
)
cache_options = common_options_parser.add_mutually_exclusive_group()
cache_options.add_argument(
    '--no-cache',
    action='store_const',
    const=None,
    dest='cache_directory',
    default=argparse.SUPPRESS,
)
cache_options.add_argument(
    '--cache-directory',
    help=f'Cache directory (default is {config.DEFAULT_CACHE_DIRECTORY})',
    type=Path,
    default=config.DEFAULT_CACHE_DIRECTORY,
)
common_options_parser.add_argument(
    '-K', '--key-file', metavar='KEYFILE', dest='key', type=_read_bytes
)
# All the different ways to provide the repository password.
# We could add a proper description for this group, but there's
# a long-standing argparse bug https://bugs.python.org/issue16807
password_options = common_options_parser.add_mutually_exclusive_group()
password_options.add_argument(
    '-p',
    '--password',
    type=os.fsencode,
    help="Password as a string. If neither password string nor the password file "
    "is provided, we'll use the REPLICAT_PASSWORD environment variable.",
)
password_options.add_argument(
    '-P',
    '--password-file',
    dest='password',
    metavar='PASSWORD_FILE_PATH',
    help="Path to a file with the password. If neither password string nor the "
    "password file is provided, we'll use the REPLICAT_PASSWORD environment variable.",
    type=_read_bytes,
)


def make_main_parser(*parent_parsers, defaults=None):
    if defaults is None:
        defaults = {}

    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument('--version', action='version', version=__version__)

    subparsers = parser.add_subparsers(dest='action', required=True)

    init_parser = subparsers.add_parser('init', parents=parent_parsers)
    init_parser.add_argument(
        '-o',
        '--key-output-file',
        help='Where to save the new repository key (the default is to write to standard output)',
        type=Path,
    )
    init_parser.set_defaults(**defaults)

    add_key_parser = subparsers.add_parser('add-key', parents=parent_parsers)
    add_key_password_options = add_key_parser.add_mutually_exclusive_group()
    add_key_password_options.add_argument('-n', '--new-password', type=os.fsencode)
    add_key_password_options.add_argument(
        '-N',
        '--new-password-file',
        dest='new_password',
        metavar='NEW_PASSWORD_FILE_PATH',
        type=_read_bytes,
    )
    add_key_parser.add_argument(
        '--shared',
        action='store_true',
        help='Whether to share encrypted chunks with the owner of that key',
    )
    add_key_parser.add_argument(
        '-o',
        '--key-output-file',
        help='Where to save the new repository key (the default is to write to standard output)',
        type=Path,
    )
    add_key_parser.set_defaults(**defaults)

    list_snapshots_parser = subparsers.add_parser(
        'list-snapshots', parents=parent_parsers, aliases=['ls']
    )
    list_snapshots_parser.add_argument(
        '-S',
        '--snapshot-regex',
        help='Regex to filter snapshots (can be specified more than once '
        'to include snapshots matching ANY of the given regexes)',
        action='append',
    )
    list_snapshots_parser.add_argument(
        '--no-header',
        help='Do not include table header in the output',
        action='store_true',
    )
    list_snapshots_parser.add_argument(
        '--columns',
        help='Comma-separated list of columns to include in the output '
        '(choices are {})'.format(', '.join(SnapshotListColumn)),
        type=SnapshotListColumn.parse_list,
    )
    list_snapshots_parser.set_defaults(**defaults)

    list_files_parser = subparsers.add_parser(
        'list-files', parents=parent_parsers, aliases=['lf']
    )
    list_files_parser.add_argument(
        '-S',
        '--snapshot-regex',
        help='Regex to filter snapshots (can be specified more than once '
        'to include snapshots matching ANY of the given regexes)',
        action='append',
    )
    list_files_parser.add_argument(
        '-F',
        '--file-regex',
        help='Regex to filter files (can be specified more than once '
        'to include files matching ANY of the given regexes)',
        action='append',
    )
    list_files_parser.add_argument(
        '--no-header',
        help='Do not include table header in the output',
        action='store_true',
    )
    list_files_parser.add_argument(
        '--columns',
        help='Comma-separated list of columns to include in the output '
        '(choices are {})'.format(', '.join(FileListColumn)),
        type=FileListColumn.parse_list,
    )
    list_files_parser.set_defaults(**defaults)

    snapshot_parser = subparsers.add_parser('snapshot', parents=parent_parsers)
    snapshot_parser.add_argument('path', nargs='+', type=Path)
    snapshot_parser.add_argument('-n', '--note')
    snapshot_parser.add_argument(
        '-L', '--limit-rate', dest='rate_limit', type=human_to_bytes
    )
    snapshot_parser.set_defaults(**defaults)

    restore_parser = subparsers.add_parser('restore', parents=parent_parsers)
    restore_parser.add_argument('path', nargs='?', help='Output directory', type=Path)
    restore_parser.add_argument(
        '-S',
        '--snapshot-regex',
        help='Regex to filter snapshots (can be specified more than once '
        'to include snapshots matching ANY of the given regexes)',
        action='append',
    )
    restore_parser.add_argument(
        '-F',
        '--file-regex',
        help='Regex to filter files (can be specified more than once '
        'to include files matching ANY of the given regexes)',
        action='append',
    )
    restore_parser.set_defaults(**defaults)

    delete_parser = subparsers.add_parser('delete', parents=parent_parsers)
    delete_parser.add_argument('snapshot', nargs='+')
    delete_parser.add_argument('-y', '--yes', action='store_true')
    delete_parser.set_defaults(**defaults)

    clean_parser = subparsers.add_parser('clean', parents=parent_parsers)
    clean_parser.set_defaults(**defaults)

    benchmark_parser = subparsers.add_parser('benchmark', parents=parent_parsers)
    benchmark_parser.add_argument('name')
    benchmark_parser.set_defaults(**defaults)

    upload_objects_parser = subparsers.add_parser(
        'upload-objects', parents=parent_parsers
    )
    upload_objects_parser.add_argument('path', nargs='+', type=Path)
    upload_objects_parser.add_argument(
        '-L', '--limit-rate', dest='rate_limit', type=human_to_bytes
    )
    upload_objects_parser.add_argument('-S', '--skip-existing', action='store_true')
    upload_objects_parser.set_defaults(**defaults)

    download_objects_parser = subparsers.add_parser(
        'download-objects', parents=parent_parsers
    )
    download_objects_parser.add_argument(
        'path', nargs='?', help='Output directory', type=Path
    )
    download_objects_parser.add_argument(
        '-O',
        '--object-regex',
        help='Regex to filter objects (can be specified more than once '
        'to include objects matching ANY of the given regexes)',
        action='append',
    )
    download_objects_parser.add_argument('-S', '--skip-existing', action='store_true')
    download_objects_parser.set_defaults(**defaults)

    list_objects_parser = subparsers.add_parser('list-objects', parents=parent_parsers)
    list_objects_parser.add_argument(
        'path', nargs='?', help='Output directory', type=Path
    )
    list_objects_parser.add_argument(
        '-O',
        '--object-regex',
        help='Regex to filter objects (can be specified more than once '
        'to include objects matching ANY of the given regexes)',
        action='append',
    )
    list_objects_parser.set_defaults(**defaults)

    delete_objects_parser = subparsers.add_parser(
        'delete-objects', parents=parent_parsers
    )
    delete_objects_parser.add_argument('object', nargs='+')
    delete_objects_parser.add_argument('-y', '--yes', action='store_true')
    delete_objects_parser.set_defaults(**defaults)
    return parser


def parser_for_backend(cls, missing=None):
    """Create a parser instance that inherits arguments from the common parser
    and adds arguments based on the class constructor signature
    """
    parser = argparse.ArgumentParser(add_help=False)
    group = parser.add_argument_group(
        f'arguments specific to the {cls.display_name} backend'
    )
    params = inspect.signature(cls).parameters

    for name, arg in params.items():
        # Take just keyword-only arguments
        if arg.kind is not arg.KEYWORD_ONLY:
            continue

        help_text = (
            f'or the {backend_env_var(cls.short_name, name)} environment variable'
        )
        if arg.default is not arg.empty:
            default = arg.default
            help_text += f', or the constructor default ({default})'
        else:
            default = missing

        name = name.replace('_', '-')
        group.add_argument(
            f'--{name}',
            # TODO: consider annotations?
            default=default,
            type=guess_type,
            help=help_text,
        )

    return parser


def parse_cli_settings(args_list):
    mapping = {}
    unknown = []
    flag = None

    for arg in args_list:
        if arg.startswith('--'):
            if flag is not None:
                unknown.append(flag)
            flag = arg
        else:
            if flag is not None:
                key = flag.lstrip('-').replace('-', '_')
                value = guess_type(arg)
                mapping[key] = value
                flag = None
            else:
                unknown.append(arg)

    if flag is not None:
        unknown.append(flag)

    return mapping, unknown
