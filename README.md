<p align='center'>
    <img src='https://i.imgur.com/1vtNQHs.png' />
</p>

<p align='center'>
    <em><strong>[ ˈrɛplɪkət ]</strong></em>
</p>

# Replicat

Configurable and lightweight backup utility with deduplication and encryption.

## Compatibility

Python 3.9 (or newer) running on Linux, MacOS, or Windows.

## Supported backup destinations

 - local path
 - Backblaze B2
 - Amazon S3
 - any S3-compatible service

You can implement and use your own adapter for pretty much any backup destination without
changing the source code of Replicat (more on that later).

## Installation

[It's available on PyPI](https://pypi.org/project/replicat), so

```bash
pip install replicat
```

## Reasoning

For various reasons, I wasn't 100% happy with any of the similar projects that I've tried.
It's likely that I will never be 100% happy with Replicat either, but at least it will be
easier for me to fix problems or add new features.

Highlights/goals:

  - efficient, concise, easily auditable implementation
  - extendable and configurable
  - few external dependencies
  - well-documented behaviour
  - unified repository layout
  - API that exists

This project borrows a few ideas from those other projects, but not enough to be considered
a copycat.

# Introduction

You can use Replicat to backup files from your machine to a *repository*, located on a *backend*
like *local* (a local path) or *b2* (Backblaze B2). Files are stored in an optionally encrypted
and chunked form, and references to *chunks* (i.e. their digests) are stored in *snapshots* along
with file name and metadata.

Replicat supports two types of repositories: encrypted (the default) and unencrypted.

Chunks, snapshots, and all other pieces of data inside unencrypted repositories are stored
unencrypted. The storage names for chunks and snapshots are simply the hash digests of their
contents.

Currently, the only supported type of encryption is symmetric encryption. To use symmetric encryption
you will need a key and the password associated with that key. A key contains parameters for the
KDF and an encrypted section, which can only be decrypted by the owner of the key using the matching
password. That section contains secrets for the cryptographic primitives that control how the data
is split into chunks, visibility of chunks of data, and more.

You can create multiple keys with different passwords and settings. When adding a new key to a
repository with symmetric encryption, you'll have to unlock it with one of the existing keys.
You have a choice to either share secrets with the other key OR generate new secrets. Owners of
keys with shared secrets ("shared" keys) can use deduplication features *together*, i.e., chunks
of data that were uploaded by the owner of one such key can be accessed and decrypted by the owner
of the other key. Assume that they will also be able to check whether you have a specific piece
of data. To avoid such risk, you can create a key with new secrets (an "independent" key).
That way, Replicat will isolate your data and make it inaccessible to the owners of other keys.
Of course, if you use your key to create a yet another (new) key, you will also have the ability
to share your secrets with others, even if they were originally copied from some other key.
This creates a web of trust of sorts.

In contrast with unencrypted repositories, the storage name for the chunk is derived from
the hash digest of its contents **and** one of the aforementioned secrets, in order to reduce
the chance of successful "confirmation of file" attacks. The chunk itself is encrypted with
the combination of the hash digest of its contents **and** another one of those secrets, since
the usual convergent encryption is vulnerable to that same "confirmation of file" attack. Table
of chunk references inside a snapshot is encrypted similarly, but the list of files that reference
those chunks is encrypted using the key and the password that were used to unlock the repository,
and therefore can only be decrypted by the owner of that key (even in the case of shared secrets).
A snapshot created using an independent key will not be visible. A snapshot created using a
shared key will be visible, but there will be no available information about it beyond its storage
name and the table of chunk references.

# Command line interface

The installer will create the `replicat` command (same as `python -m replicat`).
There are several available subcommands:

 - `init` -- initializes the repository using the provided settings
 - `snapshot` -- creates a new snapshot in the repository
 - `list-snapshots`/`ls` -- lists snapshots
 - `list-files`/`lf` -- lists files across snapshots
 - `restore` -- restores files from snapshots
 - `add-key` -- creates a new key for the encrypted repository
 - `delete` -- deletes snapshots by their names
 - `clean` -- performs garbage collection
 - `upload` -- uploads files to the backend (no chunking, no encryption, keeping original names)

It's always safe to read from and upload to a Replicat repository concurrently. In order to
make it possible for you to run destructive actions (`delete`, `clean`) concurrently with
uploads and reads, Replicat uses lock-based guards. Here's what you should know:

 - locks are designed to protect the integrity of data in the case of concurrent operations
 performed with shared keys (or, naturally, the same key), meaning that locks do not lock
 the whole repository, unless the repository is unencrypted. If you're sure that you're
 the sole user of the repository, or that no one is using the repository with the same
 (or shared) key at the same time, then you can safely use the repository in exclusive mode

 - Replicat will terminate if it detects a conflicting operation being performed with
 the same (or shared) key. It may have to wait a few extra seconds to make sure all of the
 locks are visible

 - during shutdown Replicat will attempt to delete the locks it created

There are several command line arguments that are common to all subcommands:

 - `-r`/`--repository` -- used to specify the type and location of the repository backend
 (backup destination). The format is `<backend>:<connection string>`, where `<backend>` is
 the short name of a Replicat-compatible backend and `<connection string>` is open to
 interpretation by the adapter for the selected backend. Examples:
 `b2:bucket-name` for the B2 backend or `local:some/local/path` for the local backend
 (or just `some/local/path`, since the `<backend>:` part can be omitted for local
 destinations). If the backend requires additional arguments, they will appear in the
 `--help` output. Refer to the section on backends for more detailed information.

 - `-x`/`--exclusive` -- enables the exclusive mode (see above)
 - `-q`/`--hide-progress` -- suppresses progress indication for commands that support it
 - `-c`/`--concurrent` -- the number of concurrent connections to the backend.
 Normal lock operations don't respect this limit
 - `--cache-directory` -- specifies the directory to use for cache. `--no-cache` disables
 cache completely.
 - `-v`/`--verbose` -- specifies the logging verbosity. The default verbosity is `WARNING`,
 `-v` means `INFO`, `-vv` means `DEBUG`.

Encrypted repositories require a key and a matching password for every operation:

 - `-K`/`--key-file` -- the path to the key file
 - `-p`/`--password` -- the password in plaintext. **However**, it's more secure to provide the
 password in a file via the `-P`/`--password-file` argument, or as an environment variable
 `REPLICAT_PASSWORD`.


## `init` examples

```bash
# Unencrypted repository in some/directory. The --encryption none flag disables encryption
$ replicat init -r some/directory --encryption none
# Encrypted repository with initial password taken from string.
# The new key will be printed to stdout
$ replicat init -r some/directory -p 'password string'
# Encrypted repository with initial password taken from a file.
# The new key will be written to path/to/key/file
$ replicat init -r some/directory -P path/to/password/file -o path/to/key/file
# Specifies the cipher
$ replicat init -r some/directory -p '...' --encryption.cipher.name chacha20_poly1305
# Specifies the cipher name and parameters
$ replicat init -r some/directory \
    -p '...' \
    --encryption.cipher.name aes_gcm \
    --encryption.cipher.key_bits 128
# Specifies the KDF name and parameters (for the key)
$ replicat init -r some/directory \
    -p '...' \
    --encryption.kdf.name scrypt \
    --encryption.kdf.n 1048576
# Specifies the chunking parameters
$ replicat init -r some/directory \
    -p '...' \
    --chunking.min-length 128_000 \
    --chunking.max-length 2_048_000
# Equivalent (dashes in argument names are converted to underscores)
$ replicat init -r some/directory \
    -p '...' \
    --chunking.min_length 128_000 \
    --chunking.max_length 2_048_000
```

## `snapshot` examples

```bash
# Unlocks the repository, uploads provided files in encrypted chunks,
# using no more than 10 concurrent connections, creating a snapshot
$ replicat snapshot -r some/directory \
    -P path/to/password/file \
    -K path/to/key/file \
    -c 10 \
    -n 'A note (optional)'
    image.jpg some-directory another-directory and/more.text
```

## `list-snapshots`/`ls` examples

```bash
# Unlocks the repository and lists all of the snapshots
$ replicat list-snapshots -r some/directory -P path/to/password/file -K path/to/key/file
# Equivalent
$ replicat ls -r some/directory -P path/to/password/file -K path/to/key/file
```


## `list-files`/`lf` examples

```bash
# Unlocks the repository and lists all versions of all the files
$ replicat list-files -r some/directory -P path/to/password/file -K path/to/key/file
# Equivalent
$ replicat lf -r some/directory -P path/to/password/file -K path/to/key/file
# Only lists files with paths matching the -F regex
$ replicat lf -r some/directory \
    -P path/to/password/file \
    -K path/to/key/file \
    -F '\.(jpg|text)$'
```

## `restore` examples

```bash
# Unlocks the repository and restores the latest versions of all files to target-directory
$ replicat restore -r some/directory \
    -P path/to/password/file \
    -K path/to/key/file \
    target-directory
# Unlocks the repository and restores the latest versions of files with paths matching the
# -F regex in snapshots matching the -S regex to 'target-directory'
$ replicat restore -r some/directory \
    -P path/to/password/file \
    -K path/to/key/file \
    -F '\.(jpg|text)$' \
    -S 'abcdef' \
    target-directory

```


## `add-key` examples

```bash
# Unlocks the repository and creates an independent key, which will be printed to stdout
$ replicat add-key -r some/directory -P path/to/password/file -K path/to/key/file
# Unlocks the repository and creates a shared key (i.e. with shared secrets)
$ replicat add-key -r some/directory -P path/to/password/file -K path/to/key/file --shared
# Unlocks the repository and creates an independent key, which will be written
# to path/to/new/key/file
$ replicat add-key -r some/directory \
    -P path/to/password/file \
    -K path/to/key/file \
    -o path/to/new/key/file
# Unlocks the repository and creates an independent key with some custom settings
# (cipher params as well as chunking and hashing settings are repository-wide)
$ replicat add-key -r some/directory \
    -P path/to/password/file \
    -K path/to/key/file \
    --encryption.kdf.name scrypt \
    --encryption.kdf.n 1048576
```

## `delete` examples

```bash
# Unlocks the repository and deletes snapshots by name (as returned by ls/list-snapshots).
# Chunks that aren't referenced by any other snapshot will be deleted automatically
$ replicat delete -r some/directory \
    -P path/to/password/file \
    -K path/to/key/file \
    NAME1 NAME2 NAME3 ...
```

## `clean` examples

```bash
# Unlocks the repository and deletes all chunks that are not referenced by any snapshot
$ replicat clean -r some/directory -P path/to/password/file -K path/to/key/file
```

## `upload` examples

```bash
# Uploads files directly to the backend without any additional processing.
# File path -> resulting name:
#   /working/directory/some/file -> some/file
#   /working/directory/another/file -> another/file
#   /working/directory/another/directory/another-file -> another/directory/another-file
#   /absolute/directory/path/with-file -> absolute/directory/path/with-file
#   /absolute/file -> absolute/file
/working/directory$ replicat upload -r some:repository \
                        some/file \
                        /working/directory/another/directory \
                        /absolute/directory/path \
                        /absolute/file
# Uploads files that do not yet exist in the repository (only checks the file names)
$ replicat upload -r some:repository --skip-existing some/file some/directory
```

# Backends

Run `replicat` commands with `-r <backend>:<connection string>` and additional arguments
that are specific to the selected backend. Those arguments may have defaults and may also
be provided via environment variables. Use

```bash
replicat <command> -r <backend>:<connection string> --help
```

to see them.

## Local

The format is `-r local:some/local/path` or simply `-r some/local/path`.

## B2

The format is `-r b2:bucket-id` or `-r b2:bucket-name`. This backend uses B2 native API.
The required arguments are `--key-id` (keyId) and `--application-key` (applicationKey).
Sign into your Backblaze B2 account to generate them. You can use master application key
or a normal application key (which can also be restricted to a single bucket).

## S3

The format is `-r s3:bucket-name`. Requires arguments `--key-id`, `--access-key`, and
`--region`.

## S3-compatible

The format is `-r s3c:bucket-name`. Requires arguments `--key-id`, `--access-key`,
`--region`, and `--host`. `--host` must *not* include the scheme. The default scheme is
`https`, but can be changed via the `--scheme` argument.

# Custom backends

`replicat.backends` is a namespace package, making it possible to add custom backends
without changing `replicat` source code.

Suppose your backend of choice is a hypothetical low low cost cloud storage
Proud Cloud (`pc` for short). The most barebones implementation of the
Replicat-compatible adapter for the `pc` backend will require a directory with
the following structure:

```bash
$ tree proud-cloud/
proud-cloud/
└── replicat
    └── backends
        └── pc.py
```

The `-r` argument of `replicat` commands will take the form of `-r pc:<connection string>`.
Replicat will use it to locate the `pc` module inside the `replicat.backends` package,
load the `replicat.backends.pc.Client` class, and pass the `<connection string>`
to its constructor to create the backend instance. In case there are some additional
parameters that are required to connect to Proud Cloud (account id, secret token, etc.),
you should add them to the `replicat.backends.pc.Client` constructor as keyword-only arguments.
If present, Replicat will generate the corresponding command line arguments with defaults *and*
you'll even be able to use environment variables to provide them.

`replicat.backends.pc.Client` must subclass `replicat.backends.base.Backend` and implement all
of the methods marked as abstract. You could use implementations of existing
`replicat.backends.base.Backend` subclasses as examples. To make your implementation visible
to Replicat, you'll need to add it to the module search path before invoking `replicat`
(you could use the
[`PYTHONPATH`](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONPATH) environment
variable for that).

Here's an example:

```python
# ./proud-cloud/replicat/backends/pc.py
from .base import Backend

class ProudCloud(Backend):
    def __init__(self, connection_string, *, account_id, secret, port=9_876, legacy=False):
        print(f'PC args: {connection_string=}, {account_id=}, {secret=}, {port=}, {legacy=}')
        ...
    ...

Client = ProudCloud
```

```bash
$ PYTHONPATH=proud-cloud replicat init -r pc:... --help
usage: replicat init [-h] [-r REPO] [-q] [-c CONCURRENT] [-v] [-K KEYFILE]
                     [-p PASSWORD | -P PASSWORD_FILE_PATH] [--account-id ACCOUNT_ID]
                     [--secret SECRET] [--port PORT] [--legacy LEGACY] [-o KEY_OUTPUT_FILE]

optional arguments:
  ...

arguments specific to the ProudCloud backend:
  --account-id ACCOUNT_ID
                        or the PROUDCLOUD_ACCOUNT_ID environment variable
  --secret SECRET       or the PROUDCLOUD_SECRET environment variable
  --port PORT           or the PROUDCLOUD_PORT environment variable, or the constructor default 9876
  --legacy LEGACY       or the PROUDCLOUD_LEGACY environment variable, or the constructor default False
```

```bash
$ PYTHONPATH=proud-cloud PROUDCLOUD_LEGACY=true PROUDCLOUD_SECRET='pr0ud' \
    replicat init -r pc:... \
    --account-id 12345 \
    --port 9877
PC args: connection_string='...', account_id=12345, secret='pr0ud', port=9877, legacy=True
...
```

If you've created a Replicat-compatible adapter for a backend that Replicat doesn't already
support *and* your implementation doesn't depend on additional third-party libraries
(or at least they are not too heavy and can be moved to extras), consider submitting a PR
to include it in this repository.

# Security

If you believe you've found a security issue with Replicat, please report it to
[flwaultah@gmail.com](mailto:flwaultah@gmail.com) (or DM me on Twitter or Telegram).
