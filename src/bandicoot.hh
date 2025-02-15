/* Shared data structures for server and client.
 *
 * Copyright 2025 q66 <q66@chimera-linux.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "config.hh"

#include <ctime>

#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>

/* version of dumpidx for future backwards compat changes */
enum {
    ENTRY_V1 = 1,
};

enum {
    ENTRY_FLAG_NODUMP = 1 << 0,
    ENTRY_FLAG_TRUNCATED = 1 << 1,
};

struct dumpidx {
    uint32_t version = ENTRY_V1;
    pid_t pid = 0, ipid = 0, tid = 0, itid = 0;
    uid_t uid = uid_t(-1);
    gid_t gid = gid_t(-1);
    rlim_t dumpsize = 0;
    int signum = 0;
    unsigned int pathlen = 0;
    time_t epoch = 0;
    int flags = 0;
    char comm[16];
};
