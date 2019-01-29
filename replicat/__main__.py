import asyncio
import logging
from .replicat import utils
from .replicat.repository import Repository

logger = logging.getLogger(__name__)


async def main(args, unknown):
    backend_type, connection_string = args.repo
    backend_params = utils.safe_kwargs(backend_type, vars(args))
    backend = backend_type(connection_string, **backend_params)
    repo = Repository(backend, concurrent=args.concurrent,
                    progress=args.progress)
    if args.action == 'init':
        pairs = zip(unknown[::2], unknown[1::2])
        settings = {k.lstrip('-'): utils.guess_type(v) for k, v in pairs}
        await repo.init(password=args.password, settings=settings)
    else:
        await repo.unlock(password=args.password, key=args.key)


if __name__ == '__main__':
    common, _ = utils.common_options.parse_known_args()
    backend_type, _ = common.repo
    backend_args = utils.parser_from_callable(backend_type)
    parser = utils.make_parser(utils.common_options, backend_args)
    args, unknown = parser.parse_known_args()

    if args.verbose >= 2:
        log_level = logging.DEBUG
    elif args.verbose:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    logging.basicConfig(level=log_level)
    asyncio.run(main(args, unknown))
