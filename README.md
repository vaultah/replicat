<p align='center'>
    <img src='https://i.imgur.com/1vtNQHs.png' />
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

For various reasons, I wasn't entirely happy with any of the similar projects that I've tried.

Highlights/goals of Replicat:

  - efficient, concise, easily auditable implementation
  - high customisability
  - few external dependencies
  - well-documented behaviour
  - unified repository layout
  - API that exists

This project borrows a few ideas from those other projects, but not enough to be considered
a copycat.

# Basics

You can use Replicat to backup files from your machine to a *repository*, located on a supported 
*backend* such as a local directory or cloud storage (like Backblaze B2). Files are transferred
and stored in an optionally encrypted and chunked form, and references to *chunks* are stored in
*snapshots*, along with file name and metadata.

To restore files from a snapshot, Replicat will download referenced chunks from the backend and
use them to assemble the original files locally.

Replicat supports two types of repositories: *encrypted* (the default) and *unencrypted*.
You may want to disable encryption if you trust your backend provider and network, for example.
Duplicate chunks are reused between snapshots to save on bandwidth and storage costs.

See [*Cryptography*](https://github.com/vaultah/replicat/wiki#cryptography) for a more in-depth look
into this, or [*Functional flow overview*](https://github.com/vaultah/replicat/wiki/Functional-flow-overview)
for the extremely cool and colorful diagrams that I worked really hard on.

# Command line interface

The installer will create the `replicat` command (same as `python -m replicat`).
There are several available subcommands:

 - [`init`](https://github.com/vaultah/replicat/wiki/Command%E2%80%90line-interface-(CLI)#init) - initialises the repository using the provided settings
 - [`snapshot`](https://github.com/vaultah/replicat/wiki/Command%E2%80%90line-interface-(CLI)#snapshot) - creates a new snapshot in the repository
 - [`list-snapshots`/`ls`](https://github.com/vaultah/replicat/wiki/Command%E2%80%90line-interface-(CLI)#list-snapshotsls) - lists snapshots
 - [`list-files`/`lf`](https://github.com/vaultah/replicat/wiki/Command%E2%80%90line-interface-(CLI)#list-fileslf) - lists files across snapshots
 - [`restore`](https://github.com/vaultah/replicat/wiki/Command%E2%80%90line-interface-(CLI)#restore) - restores files from snapshots
 - [`add-key`](https://github.com/vaultah/replicat/wiki/Command%E2%80%90line-interface-(CLI)#add-key) - creates a new key for the encrypted repository
 - [`delete`](https://github.com/vaultah/replicat/wiki/Command%E2%80%90line-interface-(CLI)#delete) - deletes snapshots by their names
 - [`clean`](https://github.com/vaultah/replicat/wiki/Command%E2%80%90line-interface-(CLI)#clean) - performs garbage collection
 - [`upload-objects`](https://github.com/vaultah/replicat/wiki/Command%E2%80%90line-interface-(CLI)#upload-objects) - uploads objects to the backend (a low-level command)
 - [`download-objects`](https://github.com/vaultah/replicat/wiki/Command%E2%80%90line-interface-(CLI)#download-objects) - downloads objects from the backend (a low-level command)
 - [`list-objects`](https://github.com/vaultah/replicat/wiki/Command%E2%80%90line-interface-(CLI)#list-objects) - lists objects at the backend (a low-level command)
 - [`delete-objects`](https://github.com/vaultah/replicat/wiki/Command%E2%80%90line-interface-(CLI)#delete-objects) - deletes objects from the backend (a low-level command)

> ⚠️ **WARNING**: it's not safe to run commands that read from or upload to the repository
> concurrently with destructive actions such as `delete` or `clean` if they are run by users
> with [shared keys](https://github.com/vaultah/replicat/wiki#keys) (or, naturally, the same key).
> For example, do **NOT** `snapshot` and `clean` at the same time, unless those actions are performed
> with independent keys.

There are several command line arguments that are common to all subcommands:

 - `-r`/`--repository` - used to specify the type and location of the repository backend
 (backup destination). The format is `<backend>:<connection string>`, where `<backend>` is
 the short name of a Replicat-compatible backend and `<connection string>` is open to
 interpretation by the adapter for the selected backend. Examples:
 `b2:bucket-name` for the B2 backend or `local:some/local/path` for the local backend
 (or just `some/local/path`, since the `<backend>:` part can be omitted for local
 destinations). If the backend requires additional arguments, they will appear in the
 `--help` output. Refer to the section on backends for more detailed information.

 - `-q`/`--hide-progress` - suppresses progress indication for commands that support it
 - `-c`/`--concurrent` - the number of concurrent connections to the backend
 - `--cache-directory` - specifies the directory to use for cache. `--no-cache` disables
 cache completely.
 - `-v`/`--verbose` - increases the logging verbosity. The default verbosity is `warning`,
 `-v` means `info`, `-vv` means `debug`.

Encrypted repositories require a key and a matching password for every operation:

 - `-K`/`--key-file` - the path to the key file
 - `-p`/`--password` - the password in plaintext. **However**, it's more secure to provide the
 password in a file via the `-P`/`--password-file` argument, or as an environment variable
 `REPLICAT_PASSWORD`.

If the backend requires additional parameters (account name, client secret, some boolean flag, or
literally anything else), you'll also be able to set them via command line arguments or
in the configuration file. Refer to [_Backends_ section](#backends) to learn more.

If you often use many of these arguments, and their values mostly stay the same between
invocations, you may find it easier to put them in a configuration file instead.
There are three arguments related to that:

 - `--profile` - load settings from this profile in the configuration file
 - `--config` - path to the configuration file (check `--help` for the default config location)
 - `--ignore-config` - ignore the configuration file

Note that values from CLI always take precedence over options from the configuration file.
Specifically, to build the final configuration, Replicat considers command line arguments, environment
variables, the configuration file (either the default one *or* the one supplied via `--config`),
and global defaults, in that order.

Names of configuration file options mostly match the long names of command line arguments
(e.g., `hide-progress = true` matches `--hide-progress`, `repository = "s3:bucket"` matches
`-r s3:bucket`), but you can always refer to the
[_Configuration file_ section](#configuration-file) for full reference.

# Configuration file

As mentioned in the [_Command line interface_ section](#command-line-interface), options that
you can put in the configuration file mostly match CLI arguments, with few exceptions.

|        Option name        |  Type   |    Supported values    |           Notes           |
|---------------------------| ------- |------------------------|---------------------------|
|**`repository`**           | string  | <code>\<backend\>:\<connection&#8239;string\></code> ||
|**`concurrent`**           | integer | Integers greater than 0 ||
|<b><code>hide&#8209;progress</code></b>| boolean | `true`, `false` ||
|<b><code>cache&#8209;directory</code></b>| path | Relative or absolute path ||
|<b><code>no&#8209;cache</code></b>| boolean | `true`, `false` ||
|**`password`**             | string  | Password as a string | Cannot be used together with `password-file` |
|<b><code>password&#8209;file</code></b>| path    | Relative or absolute path | Cannot be used together with `password` |
|**`key`**                  | string   | JSON as a string | Cannot be used together with `key-file` |
|<b><code>key&#8209;file</code></b>| path | Relative or absolute path | Cannot be used together with `key` |
|<b><code>log&#8209;level</code></b>| string | `debug`, `info`, `warning`, `error`, `critical`, `fatal` | CLI option `-v` _increases_ logging verbosity starting from `warning`, while this option lets you set _lower_ logging verbosity, such as  `error` |

If the backend requires additional parameters (account id, access key, numeric port, or literally
anything else), Replicat lets you provide them via the configuration file. For example, if you see
a backend-specific argument `--some-backend-option` in the `--help` output, the equivalent
configuration file option will be called `some-backend-option`.

Here's an example configuration file (it uses TOML syntax)

```toml
concurrent = 10
# Relative paths work
cache-directory = "~/.cache/directory/for/replicat"

[debugging]
log-level = "info"
hide-progress = true

[my-local-repo]
repository = "some/local/path"
password = "<secret>"
key = """
{
    "kdf": { ... },
    "kdf_params": { "!b": "..." },
    "private": { "!b": "..." }
}
"""
concurrent = 15
no-cache = true

[some-s3-repo]
repository = "s3:bucket-name"
key-id = "..."
access-key = "..."
region = "..."
```

Options that you specify at the top of the configuration file are defaults and they will be
inherited by all of the profiles. In the example above there are three profiles
(not including the default one): `debugging`, `my-local-repo`, `some-s3-repo`. You can tell
Replicat which profile to use via the `--profile` CLI argument.

Notice that `some-s3-repo` includes options that were not listed in the table. `key-id`,
`access-key`, `region` are the aforementioned backend-specific options for the S3 backend.
See [_Backends_](#backends).

# Backends

Run `replicat` commands with `-r <backend>:<connection string>` and additional arguments
that are specific to the selected backend. Those arguments may have defaults and may also
be provided via environment variables or profiles. Use

```bash
replicat <command> -r <backend>:<connection string> --help
```

to see them.

## Local

The format is `-r local:some/local/path` or simply `-r some/local/path`.

## B2

The format is `-r b2:bucket-id` or `-r b2:bucket-name`. This backend uses B2 native API and
requires

 - key ID (`--key-id` argument, or `B2_KEY_ID` environment variable, or `key-id` option in a
 profile)
 - application key (`--application-key` argument, or `B2_APPLICATION_KEY` environment variable, or
 `application-key` option in a profile)

Sign into your Backblaze B2 account to generate them. Note that you can use the master application
key or a normal (non-master) application key (which can also be restricted to a single bucket).
Refer to [official B2 docs](https://www.backblaze.com/b2/docs/application_keys.html) for more
information.

## S3

The format is `-r s3:bucket-name`. Requires

 - AWS key ID (`--key-id` argument, or `S3_KEY_ID` environment variable, or the `key-id` option
 in a profile)
 - AWS access key (`--access-key` argument, or `S3_ACCESS_KEY` environment variable, or `access-key`
 option in a profile)
 - region (`--region` argument, or `S3_REGION` environment variable, or `region` option in a profile)

## S3-compatible

The format is `-r s3c:bucket-name`. Requires

 - key ID (`--key-id` argument, or `S3C_KEY_ID` environment variable, or the `key-id` option
 in a profile)
 - access key (`--access-key` argument, or `S3C_ACCESS_KEY` environment variable, or `access-key`
 option in a profile)
 - host (`--host` argument, or `S3C_HOST` environment variable, or `host` option in a profile)
 - region (`--region` argument, or `S3C_REGION` environment variable, or `region` option
 in a profile)

Host must *not* include the scheme. The default scheme is `https`, but can be changed via the
`--scheme` argument (or, equivalently, the `S3C_SCHEME` environment variable or `scheme` option
in a profile).

You can use S3-compatible backend to connect to [B2](https://www.backblaze.com/b2/docs/s3_compatible_api.html),
S3, and many other cloud storage providers that offer S3-compatible API.

# Custom backends

`replicat.backends` is a namespace package, making it possible to add custom backends
without changing `replicat` source code.
See [_Custom backends_](https://github.com/vaultah/replicat/wiki/Custom-backends).

If you've created a Replicat-compatible adapter for a backend that Replicat doesn't already
support and your implementation doesn't depend on additional third-party libraries
(or at least they are not too heavy and can be moved to extras), consider submitting a PR
to include it in this repository.

# Custom settings

Replicat's default parameters and selection of cryptographic primitives should work well for
most users but they do allow for some customisation if you know what you are doing. Refer to
[_Encryption > Settings_](https://github.com/vaultah/replicat/wiki#settings) for more information.

# Security

If you believe you've found a security issue with Replicat, please report it to
[flwaultah@gmail.com](mailto:flwaultah@gmail.com) (or DM me on Twitter or Telegram).
