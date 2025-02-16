/* The program to inspect core dumps.
 *
 * Copyright 2025 q66 <q66@chimera-linux.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "bandicoot.hh"

#include <string>
#include <vector>
#include <algorithm>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <ctime>

#include <err.h>
#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#include <zstd.h>

extern char const *__progname;

static void usage(FILE *f) {
    std::fprintf(f,
        "Usage: %s [options...] [command] [arg]\n"
        "\n"
        "The following commands are recognized: list info dump\n"
        "\n"
        "The following options are accepted:\n"
        "\n"
        "-h, --help     Show this message and exit.\n"
        "\n"
        "The argument may be a PID value, a comm string, or a path.\n"
        "For 'info' and 'dump' the newest dump matching that is used.\n",
        __progname
    );
}

static struct option gnuopts[] = {
    {"help", no_argument, nullptr, 'h'},
    {0, 0, 0, 0}
};

struct dumpinfo {
    std::string metastr{};
    struct stat st{};
    int fd = -1;

    dumpinfo(std::string s, struct stat stv, int fdv) {
        metastr = std::move(s);
        st = stv;
        fd = fdv;
    }

    dumpinfo(dumpinfo &&di) {
        metastr = std::move(di.metastr);
        st = di.st;
        fd = di.fd;
        di.fd = -1;
    }

    dumpinfo &operator=(dumpinfo &&di) {
        metastr = std::move(di.metastr);
        st = di.st;
        fd = di.fd;
        di.fd = -1;
        return *this;
    }

    ~dumpinfo() {
        close(fd);
    }
};

static unsigned int maxpid = 0;
static unsigned int maxuid = 0;
static unsigned int maxgid = 0;
static unsigned long long maxsize = 0;
static int maxdate = 0;
static int maxcomm = 0;

static int do_list(std::vector<dumpinfo> &dumps) {
    char tbuf[64];
    int widths[6] = {0, 0, 0, 0, 0, 0};
    /* calculate how much space we need for time... */
    widths[0] = maxdate;
    /* for pid... */
    widths[1] = std::max(std::snprintf(tbuf, sizeof(tbuf), "%u", maxpid), 3);
    /* for uid... */
    widths[2] = std::max(std::snprintf(tbuf, sizeof(tbuf), "%u", maxuid), 3);
    /* for gid... */
    widths[3] = std::max(std::snprintf(tbuf, sizeof(tbuf), "%u", maxgid), 3);
    /* for size... */
    widths[4] = std::max(std::snprintf(tbuf, sizeof(tbuf), "%llu", maxsize), 4);
    /* for comm... */
    widths[5] = std::max(maxcomm, 4);
    /* and for path we don't care, print the header now */
    std::printf("%*s", widths[0], "TIME");
    std::printf("%*s", widths[1] + 2, "PID");
    std::printf("%*s", widths[2] + 2, "UID");
    std::printf("%*s", widths[3] + 2, "GID");
    std::printf("  SIG");
    std::printf("%*s", widths[4] + 2, "SIZE");
    std::printf("%*s", widths[5] + 2, "EXE");
    std::printf("  PATH\n");
    /* now the items */
    for (auto &di: dumps) {
        dumpidx meta;
        std::memcpy(&meta, di.metastr.data(), sizeof(meta));
        if (!meta.epoch) {
            meta.epoch = di.st.st_mtime;
        }
        auto ep = time_t(meta.epoch);
        auto tinfo = localtime(&ep);
        std::strftime(tbuf, sizeof(tbuf), "%x %X", tinfo);
        std::printf("%*s", widths[0], tbuf);
        if (meta.pid) {
            std::printf("%*u", widths[1] + 2, meta.pid);
        } else {
            std::printf("%*s", widths[1] + 2, "-");
        }
        if (meta.uid) {
            std::printf("%*u", widths[2] + 2, meta.uid);
        } else {
            std::printf("%*s", widths[2] + 2, "-");
        }
        if (meta.gid) {
            std::printf("%*u", widths[3] + 2, meta.gid);
        } else {
            std::printf("%*s", widths[3] + 2, "-");
        }
        if (meta.signum) {
            std::printf("%5u", meta.signum);
        } else {
            std::printf("    -");
        }
        std::printf("%*llu", widths[4] + 2, static_cast<unsigned long long>(di.st.st_size));
        std::memset(tbuf, 0, sizeof(meta.comm) + 1);
        std::memcpy(tbuf, meta.comm, sizeof(meta.comm));
        std::printf("%*s", widths[5] + 2, tbuf[0] ? tbuf : "-");
        auto *path = di.metastr.data() + sizeof(meta);
        std::printf("  %s\n", *path ? path : "-");
    }
    return 0;
}

static int do_info(std::vector<dumpinfo> &dumps) {
    if (dumps.empty()) {
        return 0;
    }
    auto &di = dumps[0];
    dumpidx meta;
    std::memcpy(&meta, di.metastr.data(), sizeof(meta));
    if (!meta.epoch) {
        meta.epoch = di.st.st_mtime;
    }
    char tbuf[64];
    auto ep = time_t(meta.epoch);
    auto tinfo = localtime(&ep);
    strftime(tbuf, sizeof(tbuf), "%c", tinfo);
    std::printf(" Timestamp: %s\n", tbuf);
    if (meta.pid) {
        std::printf("       PID: %u", meta.pid);
        if (meta.ipid && (meta.ipid != meta.pid)) {
            std::printf(" (initial namespace: %u)", meta.ipid);
        }
        std::printf("\n");
    }
    if (meta.tid && (meta.tid != meta.pid)) {
        std::printf("       TID: %u", meta.tid);
        if (meta.itid && (meta.itid != meta.tid)) {
            std::printf(" (initial namespace: %u)", meta.itid);
        }
        std::printf("\n");
    }
    if (meta.uid) {
        std::printf("       UID: %u\n", meta.uid);
    }
    if (meta.gid) {
        std::printf("       GID: %u\n", meta.uid);
    }
    if (meta.signum) {
        std::printf("    Signal: %u\n", meta.signum);
    }
    if (*(di.metastr.data() + sizeof(meta))) {
        std::printf("      Path: %s\n", di.metastr.data() + sizeof(meta));
    }
    std::memset(tbuf, 0, sizeof(meta.comm) + 1);
    std::memcpy(tbuf, meta.comm, sizeof(meta.comm));
    if (tbuf[0]) {
        std::printf("Executable: %s\n", tbuf);
    }
    if (meta.dumpsize) {
        std::printf("Core limit: %llu\n", static_cast<unsigned long long>(meta.dumpsize));
    }
    if (meta.flags) {
        std::printf("     Flags:");
        if (meta.flags & ENTRY_FLAG_NODUMP) {
            std::printf(" nodump");
        }
        if (meta.flags & ENTRY_FLAG_TRUNCATED) {
            std::printf(" truncated");
        }
        std::printf("\n");
    }
    std::printf(" Disk size: %llu\n", static_cast<unsigned long long>(di.st.st_size));
    return 0;
}

static int do_dump(std::vector<dumpinfo> &dumps) {
    if (dumps.empty()) {
        return 0;
    }
    auto &di = dumps[0];
    auto inbufsz = ZSTD_DStreamInSize();
    auto outbufsz = ZSTD_DStreamOutSize();
    auto ctx = ZSTD_createDCtx();
    if (!ctx) {
        warn("could not create zstd decompression context");
        return 1;
    }
    std::vector<char> inbuf;
    std::vector<char> outbuf;
    inbuf.reserve(inbufsz);
    outbuf.reserve(outbufsz);
    auto nread = inbufsz;
    std::size_t lastret = 0;
    for (;;) {
        auto readn = read(di.fd, inbuf.data(), nread);
        if (readn < 0) {
            if (errno == EINTR) {
                continue;
            }
            warn("could not read from stream");
            return 1;
        } else if (readn == 0) {
            /* eof */
            break;
        }
        ZSTD_inBuffer inp = {inbuf.data(), std::size_t(readn), 0};
        while (inp.pos < inp.size) {
            ZSTD_outBuffer outp = {outbuf.data(), outbufsz, 0};
            auto ret = ZSTD_decompressStream(ctx, &outp, &inp);
            if (ZSTD_isError(ret)) {
                warn("could not decompress stream");
                return 1;
            }
            for (;;) {
                auto wr = write(STDOUT_FILENO, outbuf.data(), outp.pos);
                if (wr < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    warn("could not write to stdout");
                    return 1;
                } else if (wr != ssize_t(outp.pos)) {
                    warnx("output truncated");
                    return 1;
                }
                break;
            }
            lastret = ret;
        }
    }
    ZSTD_freeDCtx(ctx);
    if (lastret != 0) {
        warn("reached EOF before we could finish a zstd frame");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    for (;;) {
        int idx = 0;
        auto c = getopt_long(argc, argv, "+hv", gnuopts, &idx);
        if (c == -1) {
            break;
        }
        switch (c) {
            case 'h':
                usage(stdout);
                return 0;
            default:
                std::fprintf(stderr, "%s: invalid option -- '%c'\n", __progname, c);
                usage(stderr);
                return 1;
        }
    }

    char const *cmd = "list";
    char const *carg = nullptr;

    if (argc > optind) {
        cmd = argv[optind];
        ++optind;
    }

    if (argc > optind) {
        carg = argv[optind];
        ++optind;
    }

    if (argc > (optind + 1)) {
        std::fprintf(stderr, "%s: too many arguments\n", __progname);
        usage(stderr);
        return 1;
    }

    if (
        std::strcmp(cmd, "list") &&
        std::strcmp(cmd, "info") &&
        std::strcmp(cmd, "dump")
    ) {
        std::fprintf(stderr, "%s: unknown command: '%s'\n", __progname, cmd);
        usage(stderr);
        return 1;
    }

    unsigned long scanpid = 0;
    std::string scanpath{};

    if (carg) {
        char *end = nullptr;
        scanpid = strtoul(carg, &end, 10);
        if (!end || *end) {
            scanpid = 0;
            /* not a pid, check if path */
            auto *sl = std::strchr(carg, '/');
            if (sl) {
                /* path match, replace slashes with ! */
                scanpath = carg;
                for (
                    char *p = std::strchr(scanpath.data(), '/');
                    p;
                    p = std::strchr(p + 1, '/')
                ) {
                    *p = '!';
                }
            }
        }
    }

    /* collect a list of dumps matching argument; sort this by date */

    auto crashdir = open(CRASH_DIR, O_DIRECTORY | O_PATH);
    if (crashdir < 0) {
        err(1, "failed to open '%s'", CRASH_DIR);
    }
    /* must not be path since we'll read it */
    auto crash_dfd = openat(crashdir, "bandicoot", O_DIRECTORY | O_RDONLY);
    if (crash_dfd < 0) {
        err(1, "failed to open '%s/bandicoot", CRASH_DIR);
    }
    close(crashdir);

    auto *dir = fdopendir(crash_dfd);
    if (!dir) {
        err(1, "failed to open dump directory");
    }

    std::vector<dumpinfo> dumps;
    for (dirent *de = readdir(dir); de; de = readdir(dir)) {
        /* regular files only */
        if (de->d_type != DT_REG) {
            continue;
        }
        /* we want at least that */
        if (std::strncmp(de->d_name, "core.", 5)) {
            continue;
        }
        /* and also only stuff we compressed */
        auto rdot = std::strrchr(de->d_name, '.');
        if (std::strcmp(rdot, ".zst")) {
            continue;
        }
        /* get a file descriptor */
        auto fd = openat(crash_dfd, de->d_name, O_RDONLY);
        if (fd < 0) {
            /* skip stuff we can't access, etc. */
            continue;
        }
        /* also stat it */
        struct stat st;
        if (fstat(fd, &st)) {
            close(fd);
            continue;
        }
        /* now... try getting its extended attribute block */
        dumpidx meta{};
        std::string metastr;
        auto attrsz = fgetxattr(fd, "user.bandicoot.meta", nullptr, 0);
        if (attrsz >= ssize_t(sizeof(meta))) {
            metastr.resize(attrsz);
            attrsz = fgetxattr(fd, "user.bandicoot.meta", metastr.data(), attrsz);
        }
        if (attrsz >= ssize_t(sizeof(meta))) {
            std::memcpy(&meta, metastr.data(), sizeof(meta));
        } else {
            /* reconstruct some metadata from filename if we can */
            auto *fn = de->d_name + sizeof("core"); /* dot implied due to \0 */
            /* comm value */
            auto *dot = std::strchr(fn, '.');
            char *path = nullptr;
            if (dot) {
                std::memcpy(meta.comm, fn, dot - fn);
                char *err = nullptr;
                /* pid value */
                meta.pid = strtoul(dot + 1, &err, 10);
                if (err && (*err == '.')) {
                    dot = err;
                    err = nullptr;
                    /* uid value */
                    meta.uid = strtoul(dot + 1, &err, 10);
                    if (err && (*err == '.')) {
                        /* the rest is path, until .zst */
                        path = err + 1;
                    }
                }
            }
            auto pathlen = 0;
            if (path) {
                pathlen = std::strlen(path);
                if (pathlen <= int(sizeof("zst"))) {
                    pathlen = 0;
                } else {
                    /* strip .zst */
                    pathlen -= 4;
                }
            }
            metastr.resize(sizeof(meta) + pathlen);
            memcpy(metastr.data(), &meta, sizeof(meta));
            if (pathlen) {
                memcpy(metastr.data() + sizeof(meta), path, pathlen);
            }
        }
        /* check if we match */
        if (scanpid) {
            /* pid does not match */
            if (meta.pid != scanpid) {
                close(fd);
                continue;
            }
        } else if (!scanpath.empty()) {
            /* path does not match */
            if (std::strcmp(metastr.data() + sizeof(meta), scanpath.data())) {
                close(fd);
                continue;
            }
        } else if (carg) {
            /* comm does not match */
            if (std::strcmp(meta.comm, carg)) {
                close(fd);
                continue;
            }
        }
        /* replace ! with / in path */
        char *p = metastr.data() + sizeof(meta);
        for (auto *s = std::strchr(p, '!'); s; s = std::strchr(s + 1, '!')) {
            *s = '/';
        }
        /* guess the maximums */
        if (meta.pid > maxpid) {
            maxpid = meta.pid;
        }
        if (meta.uid > maxuid) {
            maxuid = meta.uid;
        }
        if (meta.gid > maxgid) {
            maxgid = meta.gid;
        }
        if ((st.st_size > 0) && (uint64_t(st.st_size) > maxsize)) {
            maxsize = st.st_size;
        }
        char comm[17] = {};
        std::memcpy(comm, meta.comm, sizeof(meta.comm));
        auto comml = int(std::strlen(comm));
        if (comml > maxcomm) {
            maxcomm = comml;
        }
        char tbuf[64];
        time_t ep = meta.epoch;
        if (!ep) {
            ep = st.st_mtime;
        }
        auto tinfo = localtime(&ep);
        std::strftime(tbuf, sizeof(tbuf), "%x %X", tinfo);
        auto tlen = int(std::strlen(tbuf));
        if (tlen > maxdate) {
            maxdate = tlen;
        }
        dumps.emplace_back(std::move(metastr), st, fd);
    }

    /* sort by date */
    std::sort(dumps.begin(), dumps.end(), [](
        dumpinfo const &a, dumpinfo const &b
    ) {
        return (a.st.st_mtime >= b.st.st_mtime);
    });

    if (!std::strcmp(cmd, "list")) {
        return do_list(dumps);
    } else if (!std::strcmp(cmd, "info")) {
        return do_info(dumps);
    } else {
        return do_dump(dumps);
    }
}
