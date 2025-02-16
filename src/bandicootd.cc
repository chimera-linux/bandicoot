/* The control daemon. It accepts connections on its socket and receives
 * core dumps as well as provides a client interface to inspect said
 * information. Its metadata storage is only accessible to superuser
 * in a raw manner.
 *
 * The protocol for dump client:
 *
 * - '\xDDDUMP\0'
 * - 2 bytes containing metadata length (>0)
 * - metadata block as above (struct dumpidx followed by path)
 * - loop:
 *   - chunk size (4 bytes) - last chunk size will be 0 (eof)
 *   - chunk data
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

#include <vector>

#include <err.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/xattr.h>

#include <zstd.h>

enum {
    CONN_UNKNOWN = 0,
    CONN_DUMP,
    CONN_CLIENT,
};

/* selfpipe for signals */
static int sigpipe[2] = {-1, -1};
/* control socket */
static int ctl_sock = -1;
/* directory descriptor for /var/crash/bandicoot */
static int crash_dfd = -1;
/* number of threads to use for zstd */
static int zstd_threads = 0;

struct zstream {
    std::vector<unsigned char> inbuf;
    std::vector<unsigned char> outbuf;
    std::size_t inbufsz;
    std::size_t outbufsz;
    ZSTD_CCtx *ctx = nullptr;
    int outfd = -1;

    ~zstream() {
        release();
    }

    bool open(char const *fname, uid_t uid, gid_t gid) {
        /* initialize compbuffer */
        outbufsz = ZSTD_CStreamOutSize();
        outbuf.reserve(outbufsz);
        inbufsz = ZSTD_CStreamInSize();
        inbuf.reserve(inbufsz);
        ctx = ZSTD_createCCtx();
        if (!ctx) {
            warn("bandicootd: failed to create zstd ctx");
            return false;
        }
        outfd = openat(crash_dfd, fname, O_WRONLY | O_CREAT | O_TRUNC, 0700);
        if (outfd < 0) {
            warn("bandicootd: failed to open dump file for writing");
            return false;
        }
        if (fchownat(crash_dfd, fname, uid, gid, AT_SYMLINK_NOFOLLOW) < 0) {
            warn("bandicootd: failed to set ownership of dump file");
            /* not an error, just leave it as root */
        }
        auto errc = ZSTD_CCtx_setParameter(ctx, ZSTD_c_compressionLevel, 3);
        if (ZSTD_isError(errc)) {
            warnx("bandicootd: failed to set zstd compression level");
            return false;
        }
        errc = ZSTD_CCtx_setParameter(ctx, ZSTD_c_checksumFlag, 1);
        if (ZSTD_isError(errc)) {
            warnx("bandicootd: failed to set zstd checksum flag");
            return false;
        }
        /* we already pre-sanitized the count */
        errc = ZSTD_CCtx_setParameter(ctx, ZSTD_c_nbWorkers, zstd_threads);
        if (ZSTD_isError(errc)) {
            warnx("bandicootd: failed to set zstd thread count, using default");
            /* not an error, as it's not crucial */
        }
        return true;
    }

    bool write_from(int fd, uint32_t &datalen, std::size_t &writelen, rlim_t limit) {
        void *ptr = inbuf.data();
        auto space = (writelen < limit) ? (limit - writelen) : 0;
        auto maxread = (inbufsz > datalen) ? std::size_t(datalen) : inbufsz;
        if (maxread > space) {
            maxread = space;
        }
        auto wsize = read(fd, ptr, maxread);
        if (wsize < 0) {
            if ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                /* try again later */
                return true;
            }
            warn("bandicootd: failed to read from socket");
            return false;
        }
        /* shrink the remaining chunk */
        datalen -= wsize;
        writelen += wsize;
        ZSTD_inBuffer inp{ptr, std::size_t(wsize), 0};
        std::size_t rem;
        do {
            ZSTD_outBuffer outp{outbuf.data(), outbufsz, 0};
            rem = ZSTD_compressStream2(
                ctx, &outp, &inp, wsize ? ZSTD_e_continue : ZSTD_e_end
            );
            if (ZSTD_isError(rem)) {
                return false;
            }
            if (outp.pos != 0) {
                auto ret = write(outfd, outbuf.data(), outp.pos);
                if (ret < 0) {
                    return false;
                }
            }
        } while (wsize ? (inp.pos != inp.size) : rem);
        return true;
    }

    int release() {
        if (outfd < 0) {
            return -1;
        }
        ZSTD_freeCCtx(ctx);
        inbuf.clear();
        outbuf.clear();
        ctx = nullptr;
        auto ret = outfd;
        outfd = -1;
        return ret;
    }
};

struct conn {
    char initial[8] = {};
    uint16_t metalen = 0;
    uint16_t metagot = 0;
    uint32_t datalen = 0;
    uint32_t datagot = 0;
    int type = CONN_UNKNOWN;
    int fd = -1;
    std::size_t writelen = 0;
    char const *path = nullptr;
    std::string meta;
    dumpidx entry;
    zstream zs;

    void finish() {
        int fd = zs.release();
        /* save whichever parameters we can as xattrs */
        if (fsetxattr(fd, "user.bandicoot.meta", meta.data(), meta.size(), 0) < 0) {
            warn("bandicootd: failed to set dump xattr for %d", fd);
        }
        close(fd);
    }
};

/* event loop fds */
static std::vector<pollfd> fds{};
/* connections being established */
static std::vector<conn> conns{};

static void sig_handler(int sign) {
    write(sigpipe[1], &sign, sizeof(sign));
}

static bool sock_new(char const *path, int &sock, mode_t mode) {
    sock = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sock < 0) {
        warn("socket failed");
        return false;
    }

    std::printf("socket: created %d for %s\n", sock, path);

    sockaddr_un un;
    std::memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;

    auto plen = std::strlen(path);
    if (plen >= sizeof(un.sun_path)) {
        warnx("socket path '%s' too long", path);
        close(sock);
        return false;
    }

    std::memcpy(un.sun_path, path, plen + 1);
    /* no need to check this */
    unlink(path);

    if (bind(sock, reinterpret_cast<sockaddr const *>(&un), sizeof(un)) < 0) {
        warn("bind failed");
        close(sock);
        return false;
    }

    std::printf("socket: bound %d for %s\n", sock, path);

    if (chmod(path, mode) < 0) {
        warn("chmod failed");
        goto fail;
    }

    if (listen(sock, SOMAXCONN) < 0) {
        warn("listen failed");
        goto fail;
    }

    std::printf("socket: done\n");
    return true;

fail:
    unlink(path);
    close(sock);
    return false;
}

static bool handle_dump(conn &nc, int fd) {
    /* perhaps still reading metadata */
    if (nc.metalen) {
        /* read some amount */
        auto rn = read(fd, nc.meta.data() + nc.metagot, nc.metalen);
        if (rn == 0) {
            warnx("bandicootd: reached EOF before exhausting metadata for %d", fd);
            return false;
        } else if (rn < 0) {
            if (
                (errno == EAGAIN) ||
                (errno == EWOULDBLOCK) ||
                (errno == EINTR)
            ) {
                /* next time... */
                return true;
            }
            warn("bandicootd: read error for %d", fd);
            return false;
        }
        /* we got some stuff */
        nc.metagot += rn;
        nc.metalen -= rn;
        return true;
    }
    /* fill the index structure if we haven't yet */
    if (!nc.entry.pid) {
        std::uint32_t mver;
        std::memcpy(&mver, nc.meta.data(), sizeof(mver));
        switch (mver) {
            case ENTRY_V1:
                break;
            default:
                warnx("bandicootd: received invalid metadata ver for %d", fd);
                return false;
        }
        std::memcpy(&nc.entry, nc.meta.data(), sizeof(nc.entry));
        auto remlen = nc.meta.size() - sizeof(nc.entry);
        if ((remlen != nc.entry.pathlen) || !nc.entry.pid) {
            warnx("bandicootd: received corrupt metadata for %d", fd);
            return false;
        }
        /* the rest is the path */
        nc.path = nc.meta.data() + sizeof(nc.entry);
        /* initialize zstd stream; first make up the file name */
        constexpr auto maxfn = 255;
        char buf[maxfn + 1];
        std::snprintf(
            buf, sizeof(buf), "core.%s.%u.%u", nc.entry.comm,
            unsigned(nc.entry.pid), unsigned(nc.entry.uid)
        );
        auto flen = std::strlen(buf);
        auto plen = nc.path ? std::strlen(nc.path) : 0;
        auto *eptr = &buf[flen];
        /* total space minus what we already need minus .zst + extra . */
        auto espace = maxfn - flen - 5;
        if (espace > plen) {
            espace = plen;
        }
        if (espace) {
            *eptr++ = '.';
            memcpy(eptr, nc.path, espace);
            eptr += espace;
        }
        memcpy(eptr, ".zst", 5);
        if (!nc.zs.open(buf, nc.entry.uid, nc.entry.gid)) {
            return false;
        }
        /* it's nodump; do not save */
        if (nc.entry.flags & ENTRY_FLAG_NODUMP) {
            nc.finish();
            return false;
        }
        /* disabled via resource limit */
        if (nc.entry.dumpsize <= 0) {
            nc.finish();
            return false;
        }
    }
    /* try getting a data chunk */
    if (nc.datagot < sizeof(nc.datalen)) {
        unsigned char *dptr;
        uint32_t *gptr = &nc.datalen;
        std::memcpy(&dptr, &gptr, sizeof(void *));
        auto nread = read(fd, dptr + nc.datagot, sizeof(nc.datalen) - nc.datagot);
        if (nread < 0) {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR)) {
                return true;
            }
            warn("bandicootd: read error for %d", fd);
            return false;
        } else if (nread == 0) {
            warn("bandicootd: unexpected EOF for %d", fd);
            return false;
        }
        nc.datagot += nread;
        if (nc.datagot < sizeof(nc.datalen)) {
            /* try again next time... */
            return true;
        }
        /* if it's 0, it means we have no more chunks */
        if (nc.datalen == 0) {
            if (!nc.zs.write_from(fd, nc.datalen, nc.writelen, nc.entry.dumpsize)) {
                nc.finish();
                return false;
            }
            nc.finish();
            /* send a terminating message back to the client */
            unsigned char msg = 0xDD;
            for (;;) {
                errno = 0;
                auto wret = write(fd, &msg, sizeof(msg));
                if (wret <= 0) {
                    if (
                        (errno == EAGAIN) ||
                        (errno == EWOULDBLOCK) ||
                        (errno == EINTR)
                    ) {
                        continue;
                    }
                    warn("bandicootd: failed to write terminating message for %d", fd);
                    return false;
                }
                break;
            }
            /* discard the connection (we are done) but not actually an error */
            return false;
        }
    }
    /* reading a dump; XXX truncate when going over ulimit? */
    auto ret = nc.zs.write_from(fd, nc.datalen, nc.writelen, nc.entry.dumpsize);
    /* exhausted the chunk, reset to get a new chunk */
    if (nc.datalen == 0) {
        nc.datagot = 0;
    }
    /* ran out of space, so it's truncated */
    if (nc.writelen >= nc.entry.dumpsize) {
        nc.entry.flags |= ENTRY_FLAG_TRUNCATED;
        return false;
    }
    return ret;
}

int main() {
    {
        utsname ubuf;
        if (uname(&ubuf)) {
            err(1, "could not get uname");
        }
        char *str = ubuf.release;
        char *err = nullptr;
        auto maj = std::strtoul(str, &err, 10);
        if ((maj < 5) || !err || (*err != '.')) {
            errx(1, "kernels older than 5.x are not supported");
        }
        if (maj == 5) {
            str = err + 1;
            err = nullptr;
            auto min = std::strtoul(str, &err, 10);
            if (min < 3) {
                errx(1, "kernels older than 5.3 are not supported");
            }
        }
    }

    {
        struct sigaction sa{};
        sa.sa_handler = sig_handler;
        sa.sa_flags = SA_RESTART;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGTERM, &sa, nullptr);
        sigaction(SIGINT, &sa, nullptr);

        if (pipe(sigpipe) < 0) {
            warn("pipe failed");
            return 1;
        }
        auto &pfd = fds.emplace_back();
        pfd.fd = sigpipe[0];
        pfd.events = POLLIN;
        pfd.revents = 0;
    }

    std::printf("bandicootd: start\n");

    /* control socket */
    {
        if (!sock_new(SOCKET_PATH, ctl_sock, 0777)) {
            return 1;
        }
        auto &pfd = fds.emplace_back();
        pfd.fd = ctl_sock;
        pfd.events = POLLIN;
        pfd.revents = 0;
    }

    fds.reserve(16);
    conns.reserve(16);

    {
        cpu_set_t cset;
        sched_getaffinity(0, sizeof(cset), &cset);
        zstd_threads = CPU_COUNT(&cset);
        /* above 6 threads it does not really matter */
        if (zstd_threads > 6) {
            zstd_threads = 6;
        }
        /* adjust according to what this libzstd build permits */
        auto bounds = ZSTD_cParam_getBounds(ZSTD_c_nbWorkers);
        if (zstd_threads < bounds.lowerBound) {
            zstd_threads = bounds.lowerBound;
        } else if (zstd_threads > bounds.upperBound) {
            zstd_threads = bounds.upperBound;
        }
    }

    std::printf("bandicootd: directory setup\n");

    /* this one must be preexisting... */
    auto crashdir = open(CRASH_DIR, O_DIRECTORY | O_PATH);
    if (crashdir < 0) {
        warn("failed to open '%s'", CRASH_DIR);
        return 1;
    }
    mkdirat(crashdir, "bandicoot", 0700);
    crash_dfd = openat(crashdir, "bandicoot", O_DIRECTORY | O_PATH);
    if (crash_dfd < 0) {
        warn("failed to open '%s/bandicoot", CRASH_DIR);
        return 1;
    }
    /* don't need it anymore */
    close(crashdir);

    std::printf("bandicootd: main loop\n");

    int ret = 0;
    for (;;) {
        std::size_t ni = 0;
        std::printf("bandicootd: poll\n");
        auto pret = poll(fds.data(), fds.size(), -1);
        if (pret < 0) {
            if (errno == EINTR) {
                goto do_compact;
            }
            warn("poll failed");
            ret = 1;
            break;
        } else if (pret == 0) {
            goto do_compact;
        }
        /* signal fd */
        if (fds[ni].revents == POLLIN) {
            int sign;
            if (read(fds[ni].fd, &sign, sizeof(sign)) != sizeof(sign)) {
                warn("signal read failed");
                goto do_compact;
            }
            /* sigterm or sigint */
            break;
        }
        /* check for incoming connections */
        if (fds[++ni].revents) {
            for (;;) {
                auto afd = accept4(fds[ni].fd, nullptr, nullptr, SOCK_NONBLOCK);
                if (afd < 0) {
                    if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
                        warn("accept4 failed");
                    }
                    break;
                }
                auto &rfd = fds.emplace_back();
                rfd.fd = afd;
                rfd.events = POLLIN | POLLHUP;
                rfd.revents = 0;
                std::printf("bandicootd: accepted %d\n", afd);
            }
        }
        /* handle connections */
        for (std::size_t i = ni + 1; i < fds.size(); ++i) {
            conn *nc = nullptr;
            if (fds[i].revents == 0) {
                continue;
            }
            if (fds[i].revents & POLLHUP) {
                std::printf("bandicootd: term %d\n", fds[i].fd);
                goto bad_msg;
            }
            if (fds[i].revents & POLLIN) {
                /* look up if we already have a connection */
                for (auto &cnc: conns) {
                    if (cnc.fd == fds[i].fd) {
                        nc = &cnc;
                        break;
                    }
                }
                if (!nc) {
                    /* got none, make one */
                    nc = &conns.emplace_back();
                    nc->fd = fds[i].fd;
                }
                if (!nc->initial[0]) {
                    /* ensure we read all 8 bytes */
                    if (read(
                        fds[i].fd, nc->initial, sizeof(nc->initial)
                    ) != sizeof(nc->initial)) {
                        warnx("bandicootd: incomplete initial packet for %d", fds[i].fd);
                        goto bad_msg;
                    }
                    /* ensure the message is good */
                    if (
                        (static_cast<unsigned char>(nc->initial[0]) != 0xDD) ||
                        nc->initial[sizeof(nc->initial) - 1]
                    ) {
                        warnx("bandicootd: invalid initial packet for %d", fds[i].fd);
                        goto bad_msg;
                    }
                    if (!std::strncmp(&nc->initial[1], "DUMP", 4)) {
                        /* only accept from root */
                        struct ucred cr;
                        socklen_t crl = sizeof(cr);
                        if (getsockopt(
                            fds[i].fd, SOL_SOCKET, SO_PEERCRED, &cr, &crl
                        ) || (crl != sizeof(cr))) {
                            warn("bandicootd: failed to get socket peer credentials");
                            goto bad_msg;
                        }
                        if (cr.uid != 0) {
                            /* silently kick the connection */
                            goto bad_msg;
                        }
                        /* this is a dump message */
                        std::memcpy(&nc->metalen, &nc->initial[6], sizeof(nc->metalen));
                        if (nc->metalen < sizeof(dumpidx)) {
                            warnx("bandicootd: wrong metadata length for %d", fds[i].fd);
                            goto bad_msg;
                        }
                        /* we track this on our own... */
                        nc->meta.resize(nc->metalen);
                        nc->type = CONN_DUMP;
                        /* move on... */
                        continue;
                    }
                    warnx("bandicootd: invalid message for %d", fds[i].fd);
                    goto bad_msg;
                }
                switch (nc->type) {
                    case CONN_DUMP:
                        if (!handle_dump(*nc, fds[i].fd)) {
                            goto bad_msg;
                        }
                        continue;
                    default:
                        /* unreachable */
                        abort();
                        break;
                };
bad_msg:
                if (nc) {
                    for (auto it = conns.begin(); it != conns.end(); ++it) {
                        if (it->fd == nc->fd) {
                            conns.erase(it);
                            break;
                        }
                    }
                }
                close(fds[i].fd);
                fds[i].fd = -1;
                fds[i].revents = 0;
            }
        }
do_compact:
        if (ret) {
            break;
        }
        std::printf("bandicootd: loop compact\n");
        for (auto it = fds.begin(); it != fds.end();) {
            if (it->fd == -1) {
                it = fds.erase(it);
            } else {
                ++it;
            }
        }
        for (auto it = conns.begin(); it != conns.end();) {
            if (it->fd == -1) {
                it = conns.erase(it);
            } else {
                ++it;
            }
        }
    }
    /* close control socket and signal fd */
    close(fds[0].fd);
    close(fds[1].fd);
    /* close connections */
    for (auto &cnc: conns) {
        close(cnc.fd);
    }
    close(crash_dfd);
    std::printf("bandicootd: exit with %d\n", ret);
    /* intended return code */
    return ret;
}
