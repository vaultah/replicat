import argparse
import asyncio
import logging

from . import utils
from .repository import Repository

logger = logging.getLogger(__name__)


async def _cmd_handler(args, unknown, error):
    backend_type, connection_string = args.repo
    backend_params = utils.safe_kwargs(backend_type, vars(args))
    backend = backend_type(connection_string, **backend_params)
    repository = Repository(backend, concurrent=args.concurrent, quiet=args.quiet)

    if unknown:
        if args.action not in {'init', 'benchmark', 'add-key'}:
            error('unrecognized arguments: ' + ' '.join(unknown))
        settings = utils.flat_to_nested(utils.parse_unknown_args(unknown))
    else:
        settings = None

    if args.action == 'init':
        await repository.init(
            password=args.password,
            settings=settings,
            key_output_path=args.key_output_file,
        )
    elif args.action == 'benchmark':
        await repository.benchmark(args.name, settings=settings)
    elif args.action == 'upload':
        await repository.upload(
            args.path, rate_limit=args.rate_limit, skip_existing=args.skip_existing
        )
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
                snapshot_regex=args.snapshot_regex,
                files_regex=args.files_regex,
                path=args.path,
            )
        elif args.action == 'delete':
            await repository.delete_snapshots(args.snapshot)
        elif args.action == 'clean':
            await repository.clean()
        elif args.action in {'lf', 'list-files'}:
            await repository.list_files(
                snapshot_regex=args.snapshot_regex,
                files_regex=args.files_regex,
            )
        elif args.action in {'ls', 'list-snapshots'}:
            await repository.list_snapshots(snapshot_regex=args.snapshot_regex)

    await repository.close()


def main():
    args = argparse.Namespace()

    # Start by obtaining the repository backend type and location
    _, remaining_args = utils.repository_parser.parse_known_args(namespace=args)

    # Create the main parser incorporating common and backend-specific options
    backend_args_parser = utils.parser_from_backend_class(
        args.repo[0], inherit_common=False
    )
    main_parser = utils.make_main_parser(
        utils.common_options_parser, backend_args_parser
    )
    _, unknown = main_parser.parse_known_args(remaining_args, namespace=args)

    if args.verbose >= 2:
        log_level = logging.DEBUG
    elif args.verbose:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    logging.basicConfig(level=log_level)
    logging.getLogger('backoff').addHandler(logging.StreamHandler())
    logging.getLogger('backoff').setLevel(log_level)

    asyncio.run(_cmd_handler(args, unknown, main_parser.error))


if __name__ == '__main__':
    main()
