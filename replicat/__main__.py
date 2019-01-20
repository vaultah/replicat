import asyncio
import logging
from .replicat import utils
from .replicat.repository import Repository


logger = logging.getLogger(__name__)


async def main(args):
    backend_type, connection_string = args.storage
    backend_params = utils.safe_kwargs(backend_type, vars(args))
    backend = backend_type(connection_string, **backend_params)
    repo = Repository(backend)


if __name__ == '__main__':
    common_args, _ = utils.common_parser.parse_known_args()
    # Parse the arguments again with a backend-specific parser
    backend_type, _ = common_args.storage
    parser = utils.make_parser(backend_type)
    args = parser.parse_args()

    if args.verbose >= 2:
        log_level = logging.DEBUG
    elif args.verbose:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    logging.basicConfig(level=log_level)

    asyncio.run(main(args))
