<p align='center'>
    <img src='https://i.imgur.com/1vtNQHs.png' />
</p>

# Replicat

Configurable and lightweight backup utility with deduplication, encryption and stuff.

## Reasoning

For various reasons, I wasn't 100% happy with any of the similar projects that I've tried.
Sure, I won't be 100% happy with Replicat either, but at least I'm able to change something in it.

Highlights/goals

  - concise and efficient implementation
  - easily extendable and configurable
  - few external dependencies
  - well-documented behaviour
  - unified repository layout
  - modular design
  - API that exists

This project borrows heavily from those other projects, but not enough to be considered
a copycat 😉

# Introduction

You can use Replicat to backup files from your machine to a remote location called a *repository*,
located on a *backend* like *local* (a local path) or *b2* (Backblaze B2). Files are stored in an
optionally encrypted and chunked form, and references to *chunks* are stored in optionally encrypted
*snapshots* along with file name and metadata.

Replicat supports two types of repositories: encrypted (by default) and unencrypted.

Chunks and all other pieces of data inside unencrypted repositories are stored unencrypted.
The storage name for the chunk is simply the hash digest of its contents.

Currently the only supported type of encryption is symmetric encryption. When adding a new key
to a repository with symmetric encryption, you'll need to unlock it with one of the existing keys.
You'll be asked to either *copy/inherit a repository secret from that other key* OR 
*generate a new secret*. Owners of keys that share a secret can use deduplication features *together*,
i.e., chunks of data that was uploaded by the owner of one key can be
accessed and decrypted by the owner of the other key. Note that they will also be able to check
if you have a specific piece of data (cue the obligatory "well, it depends"). To eliminate the
risk of it happening, *generate a new secret*. That way, Replicat will isolate your data and
make it inaccessible to the owners of other keys. Of course, if you use your key to create a
yet another (new) key, you will also have the ability to share your secret with others, whether
it was copied or newly generated. This creates a web of trust of sorts.

In contrast with unencrypted repositories, the storage name for the chunk is *derived* from the
hash digest of its contents **and** the shared secret, in order to reduce the chance of successful
"confirmation of file" attacks. The chunk itself is encrypted with the combination of the hash
digest of its contents **and** the shared secret, since the usual convergent encryption is
vulnerable to that same "confirmation of file" attack.
