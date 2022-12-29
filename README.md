<p align='center'>
    <img src='https://i.imgur.com/1vtNQHs.png' />
</p>

<p align='center'>
    <em><strong>[ ˈrɛplɪkət ]</strong></em>
</p>

# Replicat

Configurable and lightweight backup utility with deduplication and encryption.

## Compatibility

Python 3.8 (or newer) running on Linux, MacOS, or Windows.

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
  - high customizability
  - few external dependencies
  - well-documented behaviour
  - unified repository layout
  - API that exists

This project borrows a few ideas from those other projects, but not enough to be considered
a copycat.

# Introduction

You can use Replicat to backup files from your machine to a *repository*, located on a *backend*
such as a local directory or cloud storage (like Backblaze B2). Your files are transfered and stored
in an optionally encrypted and chunked form, and references to *chunks* (i.e. their hash digests)
are stored in *snapshots* along with file name and metadata.

Replicat supports two types of repositories: encrypted (the default) and unencrypted.

Chunks, snapshots, and all other pieces of data inside unencrypted repositories are stored
unencrypted. The storage names for chunks and snapshots are simply the hash digests of their
contents.

Currently, the only supported type of encryption is symmetric encryption. To use symmetric encryption,
you will need a key and the password associated with that key. A key contains parameters for the
KDF and an encrypted (private) section, which can only be decrypted by the owner of the key using
the matching password. That section contains secrets for the cryptographic primitives that control
how the data is split into chunks, visibility of chunks of data, and more.

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

## Deeper dive

You're about to see diagrams illustrating how replicat processes data, along with example contents
of the configuration file, keys, and snapshots. Here's the terminology:

 - **`Encrypt(data, key)`/`Decrypt(data, key)`** -- encrypts/decrypts `data` with the encryption key
 `key` using an authenticated encryption algorithm. It's normally used to encrypt/decrypt private
 sections in keys, as well as chunks and snapshots.

 - **`Hash(data)`** -- computes the hash digest of `data` using a hashing algorithm.
 It's used to check integrity of data and to derive encryption keys for chunks and snapshots.

 - **`Mac(data, key)`** -- computes the message authentication code for `data` using suitable `key`
 and a MAC algorithm. It's mainly used to verify ownership of chunks.

 - **`SlowKdf(ikm, salt[, context])`/`FastKdf(ikm, salt[, context])`** -- calls a "slow"/"fast" key derivation
 function to obtain an encryption key from `ikm` using `salt` and an optional `context`. As a general rule,
 replicat uses "slow" KDF for low-entropy inputs and "fast" KDF for high-entropy inputs. The output length
 will match the encryption key length of the chosen encryption algorithm.

 - **`UserKey`** -- encryption key derived as `SlowKdf(Password, UserKdfParams)`, where `Password`
 is the user's password and `UserKdfParams` is the salt. `UserKey` is used to encrypt sensitive
 personal data: private sections in keys and file metadata in snapshots.

 - **`SharedKey`**, **`SharedKdfParams`**, **`SharedMacKey`**, **`SharedChunkerKey`** -- secrets stored in
 the private sections of keys. `SharedKey` and `SharedKdfParams` are used to derive encryption keys using
 "fast" KDF (they will encrypt shared data, like chunks and chunk references). `SharedMacKey` is the MAC key.
 `SharedChunkerKey` personalises content-defined chunking (CDC) to prevent watermarking attacks.

 - **`GetChunkLocation(name, authentication_tag)`/`GetSnapshotLocation(name, authentication_tag)`** -- obtains the
 location for a chunk/snapshot using its name and the corresponding authentication tag.
 
 - **`Upload(data, location)`** -- uploads `data` to the backend to the given `location`.
 - **`Download(location)`** -- downloads data from the backend at the given `location`.
 
![replicat config](https://user-images.githubusercontent.com/4944562/172485084-e2935819-0287-442c-a71c-b2098ef12077.svg)

![replicat keys](https://user-images.githubusercontent.com/4944562/172485551-789c608b-5dfd-4846-94e7-7d88a96f19db.svg)

![replicat chunks](https://user-images.githubusercontent.com/4944562/172485100-f4dc189f-6736-4914-8fe9-51960771f122.svg)

![replicat snapshots](https://user-images.githubusercontent.com/4944562/172485108-b4d66ee8-d00d-4593-a95a-c84eef53af3e.svg)

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
 - `upload-objects` -- uploads objects to the backend (a low-level command)
 - `download-objects` -- downloads objects from the backend (a low-level command)
 - `list-objects` -- lists objects at the backend (a low-level command)
 - `delete-objects` -- deletes objects from the backend (a low-level command)

> ⚠️ **WARNING**: commands that read from or upload to the repository can safely be run
> concurrently; however, there are presently no guards in place that would make it safe
> for you to run destructive actions (`delete`, `clean`) concurrently with those actions
> *unless* you use independent keys (see the explanation above). I do plan to implement them
> soon-ish, but in the meantime **DO NOT** use shared keys (or, naturally, the same key)
> to `snapshot` and `clean` at the same time, for example.
>
> As far as the upcoming implementation of such guards, it'll be based on locks. I'm familiar
> with the lock-free deduplication strategy (like in Duplicacy), but I don't like it much.

There are several command line arguments that are common to all subcommands:

 - `-r`/`--repository` -- used to specify the type and location of the repository backend
 (backup destination). The format is `<backend>:<connection string>`, where `<backend>` is
 the short name of a Replicat-compatible backend and `<connection string>` is open to
 interpretation by the adapter for the selected backend. Examples:
 `b2:bucket-name` for the B2 backend or `local:some/local/path` for the local backend
 (or just `some/local/path`, since the `<backend>:` part can be omitted for local
 destinations). If the backend requires additional arguments, they will appear in the
 `--help` output. Refer to the section on backends for more detailed information.

 - `-q`/`--hide-progress` -- suppresses progress indication for commands that support it
 - `-c`/`--concurrent` -- the number of concurrent connections to the backend
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
# Unencrypted repository 'some:repository'. The --encryption none flag disables encryption
$ replicat init -r some:repository --encryption none
# Encrypted repository with initial password taken from string.
# The new key will be printed to stdout
$ replicat init -r some:repository -p 'password string'
# Encrypted repository with initial password taken from a file.
# The new key will be written to 'path/to/key/file'
$ replicat init -r some:repository -P path/to/password/file -o path/to/key/file
# Specifies the cipher
$ replicat init -r some:repository -p '...' --encryption.cipher.name chacha20_poly1305
# Specifies the cipher name and parameters
$ replicat init -r some:repository \
    -p '...' \
    --encryption.cipher.name aes_gcm \
    --encryption.cipher.key_bits 128
# Specifies the KDF name and parameters (for the key)
$ replicat init -r some:repository \
    -p '...' \
    --encryption.kdf.name scrypt \
    --encryption.kdf.n 1048576
# Specifies the chunking parameters
$ replicat init -r some:repository \
    -p '...' \
    --chunking.min-length 128_000 \
    --chunking.max-length 2_048_000
# Equivalent (dashes in argument names are converted to underscores)
$ replicat init -r some:repository \
    -p '...' \
    --chunking.min_length 128_000 \
    --chunking.max_length 2_048_000
```

## `snapshot` examples

```bash
# Unlocks the repository, uploads provided files in encrypted chunks,
# using no more than 10 concurrent connections, creating a snapshot
$ replicat snapshot -r some:repository \
    -P path/to/password/file \
    -K path/to/key/file \
    -c 10 \
    -n 'A note (optional)'
    image.jpg some-directory another-directory and/more.text
```

## `list-snapshots`/`ls` examples

```bash
# Unlocks the repository and lists all of the snapshots
$ replicat list-snapshots -r some:repository -P path/to/password/file -K path/to/key/file
# Same, but without the table header
$ replicat ls -r some:repository -P path/to/password/file -K path/to/key/file --no-header
# Lists snapshots with names that match any of the regexes passed via the -S/--snapshot-regex flag
# In this example, we'll only list snapshots that start with 123456 OR include substring abcdef
$ replicat ls -r some:repository \
    -P path/to/password/file \
    -K path/to/key/file \
    -S '^123456' \
    -S 'abcdef'
# Lists the snapshots, but instead of the default set of columns, displays just the snapshot name,
# the number of files in the snapshot, and the total size of the snapshot (in that order).
# Oh, there's also --no-header
$ replicat ls -r some:repository \
    -P path/to/password/file \
    -K path/to/key/file \
    --no-header \
    --columns name,file_count,size
```

## `list-files`/`lf` examples

```bash
# Unlocks the repository and lists all versions of all the files
$ replicat list-files -r some:repository -P path/to/password/file -K path/to/key/file
# Same, but without the table header
$ replicat lf -r some:repository -P path/to/password/file -K path/to/key/file --no-header
# Only lists files with paths that match any of the regexes passed via the -F/--file-regex flag
# (in this example, PNGs and text files) IF they are included in snapshots that match the
# -S regex(es) (i.e., snapshots that start with '1234beef')
$ replicat lf -r some:repository \
    -P path/to/password/file \
    -K path/to/key/file \
    -F '\.t[e]?xt$' \
    -F '\.png$' \
    -S '^1234beef'
# Lists all versions of all the files, but instead of the default set of columns, displays
# the original path of the file first, then the snapshot name, the hash digest of the file,
# and the file access time (as of the snapshot creation date)
$ replicat lf -r some:repository \
    -P path/to/password/file \
    -K path/to/key/file \
    --columns snapshot_name,path,digest,atime
```

## `restore` examples

```bash
# Unlocks the repository and restores the latest versions of all files to target directory
$ replicat restore -r some:repository \
    -P path/to/password/file \
    -K path/to/key/file \
    target-directory
# Unlocks the repository and restores the latest versions of files that match any of the
# -F regex(es) from snapshots that match any of the -S regex(es)
$ replicat restore -r some:repository \
    -P path/to/password/file \
    -K path/to/key/file \
    -F '\.jpg$' \
    -F '^/root' \
    -S 'abcdef' \
    -S '12345' \
    target-directory

```

## `add-key` examples

```bash
# Unlocks the repository and creates an independent key, which will be printed to stdout
$ replicat add-key -r some:repository -P path/to/password/file -K path/to/key/file
# Unlocks the repository and creates a shared key (i.e. with shared secrets)
$ replicat add-key -r some:repository -P path/to/password/file -K path/to/key/file --shared
# Unlocks the repository and creates an independent key, which will be written
# to path/to/new/key/file
$ replicat add-key -r some:repository \
    -P path/to/password/file \
    -K path/to/key/file \
    -o path/to/new/key/file
# Unlocks the repository and creates an independent key with some custom settings
# (cipher params as well as chunking and hashing settings are repository-wide)
$ replicat add-key -r some:repository \
    -P path/to/password/file \
    -K path/to/key/file \
    --encryption.kdf.name scrypt \
    --encryption.kdf.n 1048576
```

## `delete` examples

```bash
# Unlocks the repository and deletes snapshots by name (as returned by ls/list-snapshots).
# Chunks that aren't referenced by any other snapshot will be deleted automatically
$ replicat delete -r some:repository \
    -P path/to/password/file \
    -K path/to/key/file \
    NAME1 NAME2 NAME3 ...
# Same, but doesn't ask for confirmation
$ replicat delete -r some:repository \
    -P path/to/password/file \
    -K path/to/key/file \
    NAME1 NAME2 NAME3 ... \
    --yes
```

## `clean` examples

```bash
# Unlocks the repository and deletes all chunks that are not referenced by any snapshot
$ replicat clean -r some:repository -P path/to/password/file -K path/to/key/file
```

## `upload-objects` examples

```bash
# Uploads local files directly to the repository without any additional processing.
# File path -> resulting name:
#   '/working/directory/some/file' -> 'some/file'
#   '/working/directory/another/file' -> 'another/file'
#   '/working/directory/another/directory/another-file' -> 'another/directory/another-file'
#   '/absolute/directory/path/with-file' -> 'absolute/directory/path/with-file'
#   '/absolute/file' -> 'absolute/file'
/working/directory$ replicat upload-objects -r some:repository \
                        some/file \
                        /working/directory/another/directory \
                        /absolute/directory/path \
                        /absolute/file
# Uploads local files that do not yet exist in the repository (only checks the file names)
$ replicat upload-objects -r some:repository --skip-existing some/file some/directory
```

## `download-objects` examples

```bash
# Downloads all objects from the repository directly to the current working directory
# without any additional processing
$ replicat download-objects -r some:repository
# Same, but it downloads objects to 'different/directory' instead
$ replicat download-objects -r some:repository different/directory
# Same, but it skips objects that already exist locally (only checks the file names)
$ replicat download-objects -r some:repository --skip-existing different/directory
# Downloads objects whose paths match any the -O regex(es) (i.e., all objects inside of
# 'data' OR 'snapshots' top-level directories in the repository) to the current working
# directory, skipping existing objects
$ replicat download-objects -r some:repository -O '^data/' -O '^snapshots/' -S
```

## `list-objects` examples

```bash
# Lists all objects currently in the repository
$ replicat list-objects -r some:repository
# Only lists objects whose paths match any of the regexes passed to the -O/--object-regex flag
# (i.e., all objects inside of 'data' OR 'snapshots' top-level directories in the repository)
$ replicat list-objects -r some:repository -O '^data/' -O '^snapshots/'
```

## `delete-objects` examples

```bash
# Deletes objects by their full paths as returned by list-objects
$ replicat delete-objects -r some:repository object/path/1 object/path/2 ...
# Same, but doesn't ask for confirmation
$ replicat delete-objects -r some:repository object/path/1 object/path/2 ... -y
```

## Check version

```bash
replicat --version
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

The format is `-r b2:bucket-id` or `-r b2:bucket-name`. This backend uses B2 native API and
requires

 - key ID (`--key-id` argument or `B2_KEY_ID` environment variable)
 - application key (`--application-key` argument or `B2_APPLICATION_KEY` environment variable)

Sign into your Backblaze B2 account to generate them. Note that you can use the master application
key or a normal (non-master) application key (which can also be restricted to a single bucket).
Refer to [official B2 docs](https://www.backblaze.com/b2/docs/application_keys.html) for more
information.

## S3

The format is `-r s3:bucket-name`. Requires

 - AWS key ID (`--key-id` argument or `S3_KEY_ID` environment variable)
 - AWS access key (`--access-key` argument or `S3_ACCESS_KEY` environment variable)
 - region (`--region` argument or `S3_REGION` environment variable)

## S3-compatible

The format is `-r s3c:bucket-name`. Requires

 - key ID (`--key-id` argument or `S3C_KEY_ID` environment variable)
 - access key (`--access-key` argument or `S3C_ACCESS_KEY` environment variable)
 - host (`--host` argument or `S3C_HOST` environment variable)
 - region (`--region` argument or `S3C_REGION` environment variable)

Host must *not* include the scheme. The default scheme is `https`, but can be changed via the
`--scheme` argument (or, equivalently, the `S3C_SCHEME` environment variable).

You can use S3-compatible backend to connect to [B2](https://www.backblaze.com/b2/docs/s3_compatible_api.html),
S3, and many other cloud storage providers that offer S3-compatible API.

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
