import asyncio
import inspect
import logging

from . import utils
from .repository import Repository
from .utils import cli, config

_missing_backend_argument = object()
logger = logging.getLogger(__name__)


def _configure_logging(level):
    logging.basicConfig(level=level)
    logging.getLogger('backoff').addHandler(logging.StreamHandler())
    logging.getLogger('backoff').setLevel(level)


def _instantiate_backend(backend_type, connection_string, namespace):
    params = inspect.signature(backend_type).parameters
    kwonly = {}

    for name, arg in params.items():
        if arg.kind is not arg.KEYWORD_ONLY:
            continue

        if (value := namespace[name]) is not _missing_backend_argument:
            kwonly[name] = value

    return backend_type(connection_string, **kwonly)


def _combine_optional_regexes(value):
    return utils.combine_regexes(value) if value is not None else None


async def _cmd_handler(repository, args, settings):
    if args.action == 'init':
        await repository.init(
            password=args.password,
            settings=settings,
            key_output_path=args.key_output_file,
        )
    elif args.action == 'benchmark':
        await repository.benchmark(args.name, settings=settings)
    elif args.action == 'upload-objects':
        await repository.upload_objects(
            args.path, rate_limit=args.rate_limit, skip_existing=args.skip_existing
        )
    elif args.action == 'download-objects':
        await repository.download_objects(
            path=args.path,
            object_regex=_combine_optional_regexes(args.object_regex),
            skip_existing=args.skip_existing,
        )
    elif args.action == 'list-objects':
        await repository.list_objects(
            object_regex=_combine_optional_regexes(args.object_regex)
        )
    elif args.action == 'delete-objects':
        await repository.delete_objects(args.object, confirm=not args.yes)
    elif args.action == 'add-key':
        if args.shared:
            await repository.unlock(password=args.password, key=args.key)

        await repository.add_key(
            password=args.new_password,
            settings=settings,
            key_output_path=args.key_output_file,
            shared=args.shared,
        )
    else:
        await repository.unlock(password=args.password, key=args.key)
        if args.action == 'snapshot':
            await repository.snapshot(
                paths=args.path, note=args.note, rate_limit=args.rate_limit
            )
        elif args.action == 'restore':
            await repository.restore(
                snapshot_regex=_combine_optional_regexes(args.snapshot_regex),
                file_regex=_combine_optional_regexes(args.file_regex),
                path=args.path,
            )
        elif args.action == 'delete':
            await repository.delete_snapshots(args.snapshot, confirm=not args.yes)
        elif args.action == 'clean':
            await repository.clean()
        elif args.action in {'lf', 'list-files'}:
            await repository.list_files(
                snapshot_regex=_combine_optional_regexes(args.snapshot_regex),
                file_regex=_combine_optional_regexes(args.file_regex),
                header=not args.no_header,
                columns=args.columns,
            )
        elif args.action in {'ls', 'list-snapshots'}:
            await repository.list_snapshots(
                snapshot_regex=_combine_optional_regexes(args.snapshot_regex),
                header=not args.no_header,
                columns=args.columns,
            )

    await repository.close()


def main():
    # Start by parsing the small subset of arguments to bootstrap the CLI
    args, _ = cli.initial_parser.parse_known_args()

    # Configure logging immediately, if possible
    if args.verbose >= 2:
        _configure_logging(level=logging.DEBUG)
    elif args.verbose == 1:
        _configure_logging(level=logging.INFO)

    logger.debug('Initial CLI options are %s', vars(args))
    cfg = config.Config()
    remaining_file_options = {}

    # Add profile's standard options from the configuration file and environment
    if args.configuration_file is not None:
        logger.info(
            'Trying to load options from %s for the %s profile',
            args.configuration_file,
            args.profile or 'default',
        )
        try:
            file_options = config.read_config(
                args.configuration_file, profile=args.profile
            )
        except FileNotFoundError:
            # If the file that was explicitly provided by the user does not
            # exist, fail loudly (even if it's the path of the default config)
            if args.configuration_file is not config.DEFAULT_CONFIG_PATH:
                raise
            logger.info('Configuration file does not exist, skipping')
        else:
            logger.debug(
                'Options read from the configuration file are %s', file_options
            )
            remaining_file_options = cfg.apply_known(file_options)
    else:
        logger.info('Skipping configuration file')

    cfg.apply_env()

    # Fall back on log level from config if logging has not been configured via CLI
    if not args.verbose:
        _configure_logging(level=cfg.log_level)

    if args.repository is not None:
        cfg.repository = args.repository

    # We now know which backend we'll be using. Create backend-specific config class
    # and CLI parser with backend-specific options. Load defaults for those options
    # from the configuration file and environment variables
    backend_type, connection_string = utils.load_backend(*cfg.repository)
    backend_config_type = config.config_for_backend(
        backend_type, missing=_missing_backend_argument
    )
    backend_cfg = backend_config_type()
    unknown_file_options = backend_cfg.apply_known(remaining_file_options)
    if unknown_file_options:
        logger.warning(
            'Configuration file at %s contains unrecognized options: %s',
            args.configuration_file,
            unknown_file_options,
        )

    backend_cfg.apply_env()

    # Create the main parser incorporating all of the auxiliary parsers and setting
    # config options as parser-level defaults (they'll override argument-level defaults)
    defaults = cfg.dict()
    defaults.update(backend_cfg.dict())
    logger.info('The new defaults for CLI arguments are: %s', defaults)
    main_parser = cli.make_main_parser(
        cli.initial_parser,
        cli.common_options_parser,
        cli.parser_for_backend(backend_type),
        defaults=defaults,
    )

    # NOTE: this will parse the -r/--repository and other initial CLI arguments AGAIN.
    # In theory, we should need to only parse remaining_args, as the argparse docs make
    # an interesting claim that "if the target namespace already has an attribute set,
    # the action default [e.g. -r/--repository's default] will not over write it".
    # This claim turned out to be false. BPO-45235
    _, unknown_args = main_parser.parse_known_args(namespace=args)
    logger.info('After parsing CLI arguments again we have %s', vars(args))
    custom_settings = None

    if unknown_args and args.action in {'init', 'benchmark', 'add-key'}:
        # Assume that the unknown arguments are custom settings. Try to re-parse them
        flat_settings, unknown_args = cli.parse_cli_settings(unknown_args)
        if not unknown_args:
            custom_settings = utils.flat_to_nested(flat_settings)

    if unknown_args:
        main_parser.error('unrecognized arguments: ' + ' '.join(unknown_args))

    repository = Repository(
        _instantiate_backend(backend_type, connection_string, vars(args)),
        concurrent=args.concurrent,
        quiet=args.quiet,
        cache_directory=args.cache_directory,
    )
    asyncio.run(_cmd_handler(repository, args, custom_settings))


if __name__ == '__main__':
    main()
