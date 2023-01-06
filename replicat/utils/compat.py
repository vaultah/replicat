import random
import sys

# randbytes is just convenient. Add it to pre-3.9's Random class
if sys.version_info < (3, 9):

    class Random(random.Random):
        def randbytes(self, n):
            return self.getrandbits(n * 8).to_bytes(n, 'little')

else:
    Random = random.Random


if sys.version_info < (3, 11):
    import tomli as toml  # noqa
else:
    import tomllib as toml  # noqa
