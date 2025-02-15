/* The dump client. It generates an appropriate structure and sends it over
 * the socket to the dump server.
 *
 * Copyright 2025 q66 <q66@chimera-linux.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "bandicoot.hh"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cerrno>

#include <err.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>

static unsigned long parse_u(char const *str, char const *mark) {
    char *err = NULL;
    auto num = strtoul(str, &err, 10);
    if (!err || *err) {
        errx(1, "invalid %s value", mark);
    }
    return num;
}

static unsigned long long parse_ull(char const *str, char const *mark) {
    char *err = NULL;
    auto num = strtoull(str, &err, 10);
    if (!err || *err) {
        errx(1, "invalid %s value", mark);
    }
    return num;
}

static void write_full(int fd, void *buf, std::size_t count) {
again:
    auto ws = write(fd, buf, count);
    if (ws < 0) {
        if (errno == EINTR) {
            goto again;
        }
        err(1, "socket write failed");
    } else if (std::size_t(ws) != count) {
        errx(1, "socket EOF");
    }
}

int main(int argc, char **argv) {
    if (argc != 13) {
        errx(1, "incorrect number of arguments");
    }

    dumpidx meta;

    /* all simple integers */
    meta.pid = parse_u(argv[1], "%p");
    meta.ipid = parse_u(argv[2], "%P");
    meta.tid = parse_u(argv[3], "%i");
    meta.itid = parse_u(argv[4], "%I");
    meta.uid = parse_u(argv[5], "%u");
    meta.gid = parse_u(argv[6], "%g");
    meta.signum = parse_u(argv[7], "%s");

    /* dump time */
    meta.epoch = parse_ull(argv[8], "%t");
    /* dump ulimit */
    meta.dumpsize = parse_ull(argv[9], "%c");

    /* dumpable flag */
    meta.flags = 0;
    if (!std::strcmp(argv[10], "0")) {
        meta.flags |= ENTRY_FLAG_NODUMP;
    } else if (std::strcmp(argv[10], "1")) {
        errx(1, "invalid value for dumpable flag");
    }

    /* comm value */
    auto comml = std::strlen(argv[11]);
    memset(meta.comm, 0, sizeof(meta.comm));
    memcpy(
        meta.comm, argv[11],
        (comml > sizeof(meta.comm)) ? sizeof(meta.comm) : comml
    );

    /* and the path is last... */
    auto *path = argv[12];
    meta.pathlen = std::strlen(path);

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        err(1, "socket failed");
    }

    sockaddr_un saddr;
    std::memset(&saddr, 0, sizeof(saddr));

    saddr.sun_family = AF_UNIX;
    std::memcpy(saddr.sun_path, SOCKET_PATH, sizeof(SOCKET_PATH));

    auto tsize = sizeof(meta) + meta.pathlen;
    if (tsize > UINT16_MAX) {
        errx(1, "path name too long");
    }
    uint16_t tdsz = tsize;

    unsigned char pkt[8];
    pkt[0] = 0xDD;
    memcpy(&pkt[1], "DUMP", 5);
    memcpy(&pkt[6], &tdsz, sizeof(tdsz));

    if (connect(sock, reinterpret_cast<sockaddr const *>(&saddr), sizeof(saddr)) < 0) {
        err(1, "connect failed");
    }
    write_full(sock, pkt, sizeof(pkt));
    write_full(sock, &meta, sizeof(meta));
    write_full(sock, path, meta.pathlen);

    /* proceed to write the dump; if the server does not need any more of
     * it, it is free to close the connection anytime and any of these
     * writes may fail
     */
    char buf[65536];

    for (;;) {
        auto nread = read(STDIN_FILENO, buf, sizeof(buf));
        if (nread < 0) {
            if (errno == EINTR) {
                continue;
            }
            err(1, "failed to read from stdin");
        }
        /* chunk size */
        unsigned int clen = nread;
        write_full(sock, &clen, sizeof(clen));
        if (!clen) {
            break;
        }
        write_full(sock, buf, clen);
    }

    /* at the end acknowledge a read from the server side, this is
     * so that the server can defer the HUP to the next event loop run
     */
    for (;;) {
        auto c = read(sock, pkt, 1);
        if (c < 0) {
            if (errno == EINTR) {
                continue;
            }
            err(1, "read");
        } else if (c != 1) {
            errx(1, "read EOF");
        } else if (pkt[0] != 0xDD) {
            errx(1, "invalid message from server");
        }
    }
    return 0;
}
