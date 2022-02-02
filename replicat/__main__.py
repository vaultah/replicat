import asyncio
import logging

from .replicat import utils
from .replicat.repository import Repository

logger = logging.getLogger(__name__)


async def _cmd_handler(args, unknown):
    backend_type, connection_string = args.repo
    backend_params = utils.safe_kwargs(backend_type, vars(args))
    backend = backend_type(connection_string, **backend_params)
    repository = Repository(backend, concurrent=args.concurrent, quiet=args.quiet)

    settings = utils.flat_to_nested(utils.parse_unknown_args(unknown))

    if args.action == 'init':
        await repository.init(
            password=args.password,
            settings=settings,
            key_output_path=args.key_output_file,
        )
    elif args.action == 'benchmark':
        await repository.benchmark(args.name, settings=settings)
    elif args.action == 'upload':
        await repository.upload(args.path, rate_limit=args.rate_limit)
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
    common, _ = utils.common_options.parse_known_args()
    backend_type, _ = common.repo
    backend_args_parser = utils.parser_from_backend_class(backend_type)
    parser = utils.make_main_parser(backend_args_parser)
    args, unknown = parser.parse_known_args()

    if args.verbose >= 2:
        log_level = logging.DEBUG
    elif args.verbose:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    logging.basicConfig(level=log_level)
    logging.getLogger('backoff').addHandler(logging.StreamHandler())
    logging.getLogger('backoff').setLevel(log_level)

    asyncio.run(_cmd_handler(args, unknown))


if __name__ == '__main__':
    main()
