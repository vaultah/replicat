<p align='center'>
    <img src='https://i.imgur.com/1vtNQHs.png' />
</p>

# Replicat

Configurable and lightweight backup utility with deduplication, encryption and stuff.

## Reasoning

For various reasons, I wasn't 100% happy with any of the similar projects that I've tried.
It's likely that I will never be 100% happy with Replicat either, but at least it will be
easier for me to fix problems or add new features.

Highlights/goals

  - concise and efficient implementation
  - easily extendable and configurable
  - few external dependencies
  - well-documented behaviour
  - unified repository layout
  - API that exists

This project borrows heavily from those other projects, but not enough to be considered
a copycat.

# Introduction

You can use Replicat to backup files from your machine to a remote location called a *repository*,
located on a *backend* like *local* (a local path) or *b2* (Backblaze B2). Files are stored in an
optionally encrypted and chunked form, and references to *chunks* are stored in optionally encrypted
*snapshots* along with file name and metadata.

Replicat supports two types of repositories: encrypted (the default) and unencrypted.

Chunks and all other pieces of data inside unencrypted repositories are stored unencrypted.
The storage names for chunks and snapshots are simply the hash digests of their contents.

Currently, the only supported type of encryption is symmetric encryption. To use symmetric encryption
you will need a key and the password associated with that key. A key contains parameters for the KDF
and an encrypted section, which can only be decrypted by the owner of the key using the matching password.
That section contains secrets for the cryptographic primitives that control how the data is split into
chunks, visibility of chunks of data, and more.

You can create multiple keys with different passwords and settings. When adding a new key to a repository
with symmetric encryption, you'll have to unlock it with one of the existing keys. You have a choice
to either share secrets with the other key OR generate new secrets. Owners of keys with shared secrets
can use deduplication features *together*, i.e., chunks of data that was uploaded by the owner of one such
key can be accessed and decrypted by the owner of the other key. Assume that they will also be able to check
whether you have a specific piece of data (cue the obligatory "well, it depends"). To eliminate the risk of
that happening, you can create a key with new secrets. That way, Replicat will isolate your data and make it
inaccessible to the owners of other keys. Of course, if you use your key to create a yet another (new) key,
you will also have the ability to share your secrets with others, even if they were originally copied from
some other key. This creates a web of trust of sorts.

In contrast with unencrypted repositories, the storage name for the chunk is derived from the hash digest
of its contents **and** one of the aforementioned secrets, in order to reduce the chance of successful
"confirmation of file" attacks. The chunk itself is encrypted with the combination of the hash digest of
its contents **and** another one of those secrets, since the usual convergent encryption is vulnerable to
that same "confirmation of file" attack. Snapshots are encrypted using the key and the password, which were
used to unlock the repository, and therefore can only be decrypted by the owner of that key (even in the
case of shared secrets). A snapshot created using a different key will be visible, but there will
be no available information about it beyond its storage name.

# Command line interface

The installer will create the `replicat` command (same as `python -m replicat`).
There are several available subcommands:

 - `init` -- initializes the repository using the provided settings
 - `snapshot` -- creates a new snapshot in the repository
 - `list-snapshots`/`ls` -- lists snapshots
 - `list-files`/`lf` -- lists files across snapshots
 - `restore` -- restores files from snapshots
 - `add-key` -- creates a new key for the encrypted repository

There are several command line arguments that are common to all subcommands:

 - `-r`/`--repository` -- used to specify the type and location of the repository backend.
 The format is `<backend>:<connection string>`, where `<backend>` is the name of a
 module in the `replicat.backends` package. For example: `b2:bucket-name` (B2 backend).
 The `<backend>:` part can be omitted for the local destinations (local backend).
 The `<connection string>` part is passed directly to the `replicat.backends.<backend>.Client`
 class constructor. If `replicat.backends.<backend>.Client` expects additional backend-specific
 arguments, they will appear in the `--help` output. `replicat.backends` is a namespace package,
 making it possible to add custom backends without changing `replicat` source code.

 - `-q`/`--hide-progress` -- suppresses progress indication for commands that support it
 - `-c`/`--concurrent` -- the number of concurrent connections to the backend
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
$ replicat init -r some/directory -p '...' --chunking.min-length 123 --chunking.max-length 345
# Equivalent (dashes in argument names are converted to underscores)
$ replicat init -r some/directory -p '...' --chunking.min_length 123 --chunking.max_length 345
```

## `snapshot` examples

```bash
# Unlocks the repository, uploads provided files in encrypted chunks,
# using no more than 10 concurrent connections, creating a snapshot
$ replicat snapshot -r some/directory \
    -P path/to/password/file \
    -K path/to/key/file \
    -c 10 \
    image.jpg some-directory another-director and/more.text
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
$ replicat lf -r some/directory -P path/to/password/file -K path/to/key/file -F '.*\.(jpg|text)$'
```

## `restore` examples

```bash
# Unlocks the repository and restores the latest versions of all files to 'target-directory'
$ replicat restore -r some/directory \
    -P path/to/password/file \
    -K path/to/key/file \
    target-directory
# Unlocks the repository and restores the latest versions of files with paths matching the
# -F regex in snapshots matching the -S regex to 'target-directory'
$ replicat restore -r some/directory \
    -P path/to/password/file \
    -K path/to/key/file \
    -F '.*\.(jpg|text)$' \
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
