# bandicoot

This is a distro-independent crash dump handler for Linux. It aims to be as
simple as possible while providing a reasonable amount of control; it is
specifically written to avoid depending on shell scripts.

Core dumps are compressed with zstd and stored on the filesystem. A journal
of metadata is stored alongside, which can be used to inspect metadata.

Eventually, the system will be able to automatically prune core dumps in
a configurable manner to keep a certain size, as well as provide various
other limits and configuration. For now it does not do any of that.

**It is not ready to be used right now.**

## Building

The build-time dependencies are:

* meson
* a C++20 compiler
* scdoc (optional, to build manpages)

Additional dependencies required to build and run:

* libzstd

## How it works

The whole system consists of 3 processes:

* `bandicootd`
* `bandicoot-dump`
* `bandicoot`

The first is a daemon that runs as a system service. It opens a listening
TCP socket and accepts connections. When a connection is received, it expects
to receive a specific message.

* For connections from `bandicoot-dump`, an identification message plus metadata
  is received, followed by a stream representing a core dump. This type of
  message is only allowed from superuser connections (peer credentials are
  verified).
* For connections from `bandicoot`, a different protocol is followed. Any
  user can send these messages but it will only receive information it has
  permissions for.
