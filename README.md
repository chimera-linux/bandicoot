# bandicoot

This is a distro-independent crash dump handler for Linux. It aims to be as
simple as possible while providing a reasonable amount of control; it is
specifically written to avoid depending on shell scripts.

Core dumps are compressed with zstd and stored on the filesystem. All metadata
about the core are attached in an extended attribute on the compressed file.

**It is not ready to be used right now.**

## Building

The build-time dependencies are:

* meson
* a C++20 compiler
* scdoc (optional, to build manpages)

Additional dependencies required to build and run:

* libzstd

Kernel 5.3 or newer is required at runtime, due to older kernels having
potentially broken argument splitting when there are spaces in the path.

## How it works

The whole system consists of 3 processes:

* `bandicootd` - the server
* `bandicoot-dump` - the client
* `bandicoot` - the inspection tool

The server opens a listening socket where it expects to receive metadata
about the dump plus the dump itself, and it compresses and stores the
dump.

The client is expected to be used with the Linux kernel `core_pattern`
`sysctl` entry.

The inspection tool can read information about the core dumps as well as
extract them.
