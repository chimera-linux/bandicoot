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

#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>

int main() {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        err(1, "socket failed");
    }

    sockaddr_un saddr;
    std::memset(&saddr, 0, sizeof(saddr));

    saddr.sun_family = AF_UNIX;
    std::memcpy(saddr.sun_path, SOCKET_PATH, sizeof(SOCKET_PATH));

    dumpidx testdata;
    testdata.pid = 69;
    testdata.ipid = 32;
    testdata.tid = 420;
    testdata.itid = 85;
    testdata.uid = 1000;
    testdata.gid = 1001;
    testdata.signum = 11;
    testdata.pathlen = sizeof("usr!bin!firefox") - 1;
    testdata.epoch = 10000000;
    testdata.flags = 0;
    testdata.dumpsize = RLIM_INFINITY;
    memset(testdata.comm, 0, sizeof(testdata.comm));
    memcpy(testdata.comm, "firefox", sizeof("firefox"));

    unsigned short tdsz = sizeof(testdata) + testdata.pathlen;

    unsigned char pkt[8];
    pkt[0] = 0xDD;
    memcpy(&pkt[1], "DUMP", 5);
    memcpy(&pkt[6], &tdsz, sizeof(tdsz));

    if (connect(sock, reinterpret_cast<sockaddr const *>(&saddr), sizeof(saddr)) < 0) {
        err(1, "connect failed");
    }
    if (write(sock, pkt, sizeof(pkt)) != sizeof(pkt)) {
        err(1, "protocol write failed");
    }
    if (write(sock, &testdata, sizeof(testdata)) != sizeof(testdata)) {
        err(1, "metadata header write failed");
    }
    if (write(sock, "usr!bin!firefox", testdata.pathlen) != testdata.pathlen) {
        err(1, "metadata write failed");
    }
    unsigned int clen = sizeof("hello world");
    write(sock, &clen, sizeof(clen));
    write(sock, "hello world", clen);
    clen = 0;
    write(sock, &clen, sizeof(clen));
    /* acknowledgement from server so we don't hup early */
    read(sock, pkt, 1);
    return 0;
}
