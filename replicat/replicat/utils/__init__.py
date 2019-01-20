import argparse
import importlib
import inspect


def _storage_tuple(uri):
    parts = uri.split(':', 1)
    if len(parts) < 2:
        name, connection_string = 'local', parts[0]
    else:
        name, connection_string = parts

    mod = importlib.import_module(f'..backends.{name}', package=__package__)
    return (mod.Client, connection_string)


common_parser = argparse.ArgumentParser(add_help=False)
common_parser.add_argument('-c', '--concurrent', default=5, type=int)
common_parser.add_argument('-v', '--verbose', action='count', default=0)
common_parser.add_argument('-P', '--hide-progress', action='store_true')
common_parser.add_argument('-s', '--storage', type=_storage_tuple, required=True)


def safe_kwargs(func, args):
    params = inspect.signature(func).parameters
    return {name: args[name] for name, arg in params.items()
                if arg.kind is arg.KEYWORD_ONLY and name in args}


def make_parser(cls):
    """ Create an ArgumentParser instance based on the keyword-only
        arguments of `cls`'s constructor """
    parser = argparse.ArgumentParser(parents=[common_parser])
    params = inspect.signature(cls).parameters

    for name, arg in params.items():
        # Only take keyword-only arguments
        if arg.kind is not arg.KEYWORD_ONLY:
            continue
        default = arg.default if arg.default is not arg.empty else None
        # TODO: Consider annotations? Will inspect module eval them in Python 4.0?
        _type = type(default) if default is not None else None
        parser.add_argument(f'--{name}', required=arg.default is arg.empty,
                        default=default, type=_type)

    return parser
