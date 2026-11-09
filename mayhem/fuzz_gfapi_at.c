#define _GNU_SOURCE
/* Fuzzes libgfapi's directory-handle-relative calls (glfs_openat(), glfs_fstatat(), glfs_linkat(),
 * glfs_renameat(), ...) the way Samba's vfs_glusterfs drives them: an application opens directory
 * handles and issues a sequence of *at() calls relative to them, many of which fail.  The backend is
 * the in-process debug/fuzzfs xlator (mayhem/fuzzfs.c); the input picks the calls, the parent
 * handle and the path components.  Every handle the harness opens, it closes once. */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <glusterfs/api/glfs.h>

#ifndef FUZZFS_VOLFILE
#define FUZZFS_VOLFILE "/mayhem/mayhem/fuzzfs.volfile"
#endif

/* libglusterfs-internal switch (as gf_fuzz_init.h): plain malloc/free so ASan sees every allocation */
int gf_global_mem_acct_enable_set(int val);

static glfs_t *fs;

const char *
__asan_default_options(void)
{
    return "symbolize=0";
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    gf_global_mem_acct_enable_set(0);
    fs = glfs_new("fuzzvol");
    if (!fs)
        return 1;
    if (glfs_set_volfile(fs, FUZZFS_VOLFILE) || glfs_set_logging(fs, "/dev/null", 0) ||
        glfs_init(fs))
        return 1;
    return 0;
}

static const char *const comp[] = {"afile", "d", "f", "sub", "lnk", "missing", "..", "."};
#define NCOMP (sizeof(comp) / sizeof(comp[0]))

struct in {
    const uint8_t *p;
    size_t left;
};

static unsigned
nextb(struct in *in)
{
    if (!in->left)
        return 0;
    in->left--;
    return *in->p++;
}

/* 0-3 components of a small alphabet; zero components is the empty path (AT_EMPTY_PATH) */
static void
getpath(struct in *in, char *out)
{
    unsigned n = nextb(in) % 4, i;

    out[0] = '\0';
    for (i = 0; i < n; i++) {
        if (i)
            strcat(out, "/");
        strcat(out, comp[nextb(in) % NCOMP]);
    }
}

#define IGN(x)                                                                 \
    do {                                                                       \
        long long rc_ = (long long)(x);                                        \
        (void)rc_;                                                             \
    } while (0)

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct in in = {data, size};
    glfs_fd_t *dir[2], *fd;
    char p1[32], p2[32], buf[64];
    struct stat st;
    unsigned op, f, nops = 0;

    if (size == 5 && !memcmp(data, "CRASH", 5)) {
        volatile char *q = malloc(1);
        q[1] = 1;
    }
    if (size == 5 && !memcmp(data, "SEGV!", 5))
        *(volatile int *)0 = 1;
    if (size == 5 && !memcmp(data, "UAFH!", 5)) {
        volatile char *q = malloc(8);
        free((void *)q);
        q[0] = 1;
    }
    if (size == 5 && !memcmp(data, "OPEN1", 5)) {
        glfs_opendir(fs, "/d");
        volatile char *q = malloc(1);
        q[1] = 1;
    }
    if (size == 5 && !memcmp(data, "STAT!", 5)) {
        struct stat st0;
        glfs_stat(fs, "/afile", &st0);
        volatile char *q = malloc(1);
        q[1] = 1;
    }
    if (size == 5 && !memcmp(data, "THRD!", 5)) {
        pthread_t th;
        pthread_create(&th, 0, (void *(*)(void *))pause, 0);
        volatile char *q = malloc(1);
        q[1] = 1;
    }
    if (size < 2 || size > 128)
        return -1;

    dir[0] = glfs_opendir(fs, "/d");
    dir[1] = glfs_opendir(fs, "/");
    if (!dir[0] || !dir[1])
        return -1;

    if (size == 5 && !memcmp(data, "LATE!", 5)) {
        volatile char *q = malloc(1);
        q[1] = 1;
    }
    while (in.left && nops++ < 16) {
        op = nextb(&in);
        f = nextb(&in);
        glfs_fd_t *a = dir[(op >> 4) & 1], *b = dir[(op >> 5) & 1];

        getpath(&in, p1);
        switch (op % 13) {
            case 0:
                fd = glfs_openat(a, p1, (f & 3) | ((f & 4) ? O_CREAT : 0), 0644);
                if (fd)
                    glfs_close(fd);
                break;
            case 1:
                IGN(glfs_fstatat(a, p1, &st,
                                 ((f & 1) ? AT_SYMLINK_NOFOLLOW : 0) |
                                     ((f & 2) ? AT_EMPTY_PATH : 0)));
                break;
            case 2:
                IGN(glfs_faccessat(a, p1, f & 7, (f & 8) ? AT_SYMLINK_NOFOLLOW : 0));
                break;
            case 3:
                IGN(glfs_fchmodat(a, p1, 0600, (f & 1) ? AT_SYMLINK_NOFOLLOW : 0));
                break;
            case 4:
                IGN(glfs_fchownat(a, p1, 1000, 1000,
                                  ((f & 1) ? AT_SYMLINK_NOFOLLOW : 0) |
                                      ((f & 2) ? AT_EMPTY_PATH : 0)));
                break;
            case 5:
                getpath(&in, p2);
                IGN(glfs_linkat(a, p1, b, p2,
                                ((f & 1) ? AT_SYMLINK_FOLLOW : 0) |
                                    ((f & 2) ? AT_EMPTY_PATH : 0)));
                break;
            case 6:
                IGN(glfs_mkdirat(a, p1, 0755));
                break;
            case 7:
                IGN(glfs_mknodat(a, p1, S_IFREG | 0644, 0));
                break;
            case 8:
                IGN(glfs_readlinkat(a, p1, buf, sizeof(buf)));
                break;
            case 9:
                getpath(&in, p2);
                IGN(glfs_renameat(a, p1, b, p2));
                break;
            case 10:
                getpath(&in, p2);
                IGN(glfs_renameat2(a, p1, b, p2, f & 7));
                break;
            case 11:
                getpath(&in, p2);
                IGN(glfs_symlinkat(p1, b, p2));
                break;
            case 12:
                IGN(glfs_unlinkat(a, p1, (f & 1) ? AT_REMOVEDIR : 0));
                break;
        }
    }

    glfs_closedir(dir[0]);
    glfs_closedir(dir[1]);
    return 0;
}
