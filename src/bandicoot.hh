/* Shared data structures for server and client.
 *
 * Copyright 2025 q66 <q66@chimera-linux.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "config.hh"

#include <cstdlib>
#include <cstring>
#include <cstdint>
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
    uint32_t pid = 0, ipid = 0;
    uint32_t tid = 0, itid = 0;
    uint32_t uid = 0, gid = 0;
    uint32_t signum = 0;
    uint64_t dumpsize = 0;
    uint64_t epoch = 0;
    uint32_t pathlen = 0;
    uint32_t flags = 0;
    char comm[16] = {};

    void swap(dumpidx &dx) {
        dumpidx tmp = *this;
        *this = dx;
        dx = tmp;
    }
};

struct databuf {
    databuf() {}
    ~databuf() {
        clear();
    }

    databuf(databuf &&d) {
        swap(d);
    }

    databuf &operator=(databuf &&d) {
        swap(d);
        return *this;
    }

    databuf(databuf const &) = delete;
    databuf &operator=(databuf const &) = delete;

    void clear() {
        std::free(buf);
        buf = nullptr;
        cap = 0;
    }

    void swap(databuf &d) {
        auto *bufv = buf;
        auto capv = cap;
        buf = d.buf;
        cap = d.cap;
        d.buf = bufv;
        d.cap = capv;
    }

    bool reserve(std::size_t n) {
        void *newp = std::realloc(buf, n);
        if (!newp) {
            return false;
        }
        buf = static_cast<char *>(newp);
        cap = n;
        return true;
    }

    char *buf = nullptr;
    std::size_t cap = 0;
};

static_assert(sizeof(dumpidx) == 72, "struct dumpidx has a bad size");
