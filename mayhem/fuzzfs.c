/* debug/fuzzfs: a leaf xlator serving a tiny read-only tree, so libgfapi can run in-process without a
 * brick or glusterd (a posix brick needs trusted.* xattrs, i.e. root).  It answers lookups the way a
 * posix brick would; every mutating fop fails with EROFS.
 *
 *   /            dir      gfid ..01
 *   /d           dir      gfid ..02
 *   /afile       regular  gfid ..03
 *   /d/f         regular  gfid ..04
 *   /d/sub       dir      gfid ..05
 *   /lnk         symlink  gfid ..06  -> "d/f"
 */
#include <glusterfs/defaults.h>
#include <glusterfs/xlator.h>
#include <glusterfs/iatt.h>

struct fnode {
    const char *name;
    int parent;
    ia_type_t type;
};

static const struct fnode tree[] = {
    {"", -1, IA_IFDIR},      {"d", 0, IA_IFDIR},   {"afile", 0, IA_IFREG},
    {"f", 1, IA_IFREG},      {"sub", 1, IA_IFDIR}, {"lnk", 0, IA_IFLNK},
};
#define NNODES (int)(sizeof(tree) / sizeof(tree[0]))

static int
node_by_gfid(const uuid_t gfid)
{
    int i;

    for (i = 1; i < 16; i++)
        if (gfid[i - 1])
            return -1;
    i = gfid[15] - 1;
    return (i >= 0 && i < NNODES) ? i : -1;
}

static int
node_of_loc(loc_t *loc)
{
    int parent, i;

    if (loc->name && (!gf_uuid_is_null(loc->pargfid) || loc->parent)) {
        parent = node_by_gfid(!gf_uuid_is_null(loc->pargfid) ? loc->pargfid
                                                             : loc->parent->gfid);
        if (parent < 0)
            return -ENOENT;
        if (tree[parent].type != IA_IFDIR)
            return -ENOTDIR;
        if (!strcmp(loc->name, "."))
            return parent;
        if (!strcmp(loc->name, ".."))
            return tree[parent].parent < 0 ? 0 : tree[parent].parent;
        for (i = 1; i < NNODES; i++)
            if (tree[i].parent == parent && !strcmp(tree[i].name, loc->name))
                return i;
        return -ENOENT;
    }
    if (!gf_uuid_is_null(loc->gfid))
        i = node_by_gfid(loc->gfid);
    else if (loc->inode)
        i = node_by_gfid(loc->inode->gfid);
    else
        i = -1;
    return i < 0 ? -ENOENT : i;
}

static void
fill_iatt(struct iatt *buf, int n)
{
    memset(buf, 0, sizeof(*buf));
    buf->ia_gfid[15] = n + 1;
    buf->ia_ino = n + 1;
    buf->ia_type = tree[n].type;
    buf->ia_nlink = tree[n].type == IA_IFDIR ? 2 : 1;
    buf->ia_blksize = 4096;
    buf->ia_prot = ia_prot_from_st_mode(tree[n].type == IA_IFDIR ? 0755 : 0644);
    buf->ia_flags = IATT_TYPE | IATT_MODE | IATT_NLINK | IATT_INO | IATT_GFID;
}

int32_t
init(xlator_t *this)
{
    return 0;
}

void
fini(xlator_t *this)
{
}

int32_t
notify(xlator_t *this, int32_t event, void *data, ...)
{
    switch (event) {
        case GF_EVENT_PARENT_UP:
            default_notify(this, GF_EVENT_CHILD_UP, data);
            break;
        case GF_EVENT_PARENT_DOWN:
            default_notify(this, GF_EVENT_CHILD_DOWN, data);
            break;
        default:
            break;
    }
    return 0;
}

static int32_t
fuzzfs_lookup(call_frame_t *frame, xlator_t *this, loc_t *loc, dict_t *xdata)
{
    struct iatt buf, post;
    int n = node_of_loc(loc);

    if (n < 0) {
        STACK_UNWIND_STRICT(lookup, frame, -1, -n, NULL, NULL, NULL, NULL);
        return 0;
    }
    fill_iatt(&buf, n);
    fill_iatt(&post, tree[n].parent < 0 ? 0 : tree[n].parent);
    STACK_UNWIND_STRICT(lookup, frame, 0, 0, loc->inode, &buf, xdata, &post);
    return 0;
}

static int32_t
fuzzfs_stat(call_frame_t *frame, xlator_t *this, loc_t *loc, dict_t *xdata)
{
    struct iatt buf;
    int n = node_of_loc(loc);

    if (n < 0)
        return default_stat_failure_cbk(frame, -n);
    fill_iatt(&buf, n);
    STACK_UNWIND_STRICT(stat, frame, 0, 0, &buf, xdata);
    return 0;
}

static int32_t
fuzzfs_fstat(call_frame_t *frame, xlator_t *this, fd_t *fd, dict_t *xdata)
{
    struct iatt buf;
    int n = node_by_gfid(fd->inode->gfid);

    if (n < 0)
        return default_fstat_failure_cbk(frame, ENOENT);
    fill_iatt(&buf, n);
    STACK_UNWIND_STRICT(fstat, frame, 0, 0, &buf, xdata);
    return 0;
}

static int32_t
fuzzfs_access(call_frame_t *frame, xlator_t *this, loc_t *loc, int32_t mask,
              dict_t *xdata)
{
    int n = node_of_loc(loc);

    if (n < 0)
        return default_access_failure_cbk(frame, -n);
    STACK_UNWIND_STRICT(access, frame, 0, 0, xdata);
    return 0;
}

static int32_t
fuzzfs_readlink(call_frame_t *frame, xlator_t *this, loc_t *loc, size_t size,
                dict_t *xdata)
{
    struct iatt buf;
    int n = node_of_loc(loc);

    if (n < 0)
        return default_readlink_failure_cbk(frame, -n);
    if (tree[n].type != IA_IFLNK)
        return default_readlink_failure_cbk(frame, EINVAL);
    fill_iatt(&buf, n);
    STACK_UNWIND_STRICT(readlink, frame, 3, 0, "d/f", &buf, xdata);
    return 0;
}

static int32_t
fuzzfs_open(call_frame_t *frame, xlator_t *this, loc_t *loc, int32_t flags,
            fd_t *fd, dict_t *xdata)
{
    int n = node_of_loc(loc);

    if (n < 0)
        return default_open_failure_cbk(frame, -n);
    if (tree[n].type == IA_IFDIR)
        return default_open_failure_cbk(frame, EISDIR);
    if (flags & (O_WRONLY | O_RDWR | O_TRUNC | O_APPEND))
        return default_open_failure_cbk(frame, EROFS);
    STACK_UNWIND_STRICT(open, frame, 0, 0, fd, xdata);
    return 0;
}

static int32_t
fuzzfs_opendir(call_frame_t *frame, xlator_t *this, loc_t *loc, fd_t *fd,
               dict_t *xdata)
{
    int n = node_of_loc(loc);

    if (n < 0)
        return default_opendir_failure_cbk(frame, -n);
    if (tree[n].type != IA_IFDIR)
        return default_opendir_failure_cbk(frame, ENOTDIR);
    STACK_UNWIND_STRICT(opendir, frame, 0, 0, fd, xdata);
    return 0;
}

static int32_t
fuzzfs_flush(call_frame_t *frame, xlator_t *this, fd_t *fd, dict_t *xdata)
{
    STACK_UNWIND_STRICT(flush, frame, 0, 0, xdata);
    return 0;
}

static int32_t
fuzzfs_readdirp(call_frame_t *frame, xlator_t *this, fd_t *fd, size_t size,
                off_t off, dict_t *xdata)
{
    gf_dirent_t entries;

    INIT_LIST_HEAD(&entries.list);
    STACK_UNWIND_STRICT(readdirp, frame, 0, 0, &entries, xdata);
    return 0;
}

static int32_t
fuzzfs_setattr(call_frame_t *frame, xlator_t *this, loc_t *loc,
               struct iatt *stbuf, int32_t valid, dict_t *xdata)
{
    struct iatt pre, post;
    int n = node_of_loc(loc);

    if (n < 0)
        return default_setattr_failure_cbk(frame, -n);
    fill_iatt(&pre, n);
    fill_iatt(&post, n);
    STACK_UNWIND_STRICT(setattr, frame, 0, 0, &pre, &post, xdata);
    return 0;
}

#define EROFS_FOP(fop, ...)                                                    \
    static int32_t fuzzfs_##fop(call_frame_t *frame, xlator_t *this,           \
                                __VA_ARGS__)                                   \
    {                                                                          \
        return default_##fop##_failure_cbk(frame, EROFS);                      \
    }

EROFS_FOP(create, loc_t *loc, int32_t flags, mode_t mode, mode_t umask,
          fd_t *fd, dict_t *xdata)
EROFS_FOP(mkdir, loc_t *loc, mode_t mode, mode_t umask, dict_t *xdata)
EROFS_FOP(mknod, loc_t *loc, mode_t mode, dev_t rdev, mode_t umask,
          dict_t *xdata)
EROFS_FOP(symlink, const char *linkname, loc_t *loc, mode_t umask,
          dict_t *xdata)
EROFS_FOP(unlink, loc_t *loc, int xflags, dict_t *xdata)
EROFS_FOP(rmdir, loc_t *loc, int xflags, dict_t *xdata)
EROFS_FOP(rename, loc_t *oldloc, loc_t *newloc, dict_t *xdata)
EROFS_FOP(link, loc_t *oldloc, loc_t *newloc, dict_t *xdata)

struct xlator_fops fops = {
    .lookup = fuzzfs_lookup,
    .stat = fuzzfs_stat,
    .fstat = fuzzfs_fstat,
    .access = fuzzfs_access,
    .readlink = fuzzfs_readlink,
    .open = fuzzfs_open,
    .opendir = fuzzfs_opendir,
    .flush = fuzzfs_flush,
    .readdirp = fuzzfs_readdirp,
    .setattr = fuzzfs_setattr,
    .create = fuzzfs_create,
    .mkdir = fuzzfs_mkdir,
    .mknod = fuzzfs_mknod,
    .symlink = fuzzfs_symlink,
    .unlink = fuzzfs_unlink,
    .rmdir = fuzzfs_rmdir,
    .rename = fuzzfs_rename,
    .link = fuzzfs_link,
};

struct xlator_cbks cbks = {};

struct volume_options options[] = {
    {.key = {"read-only"},
     .type = GF_OPTION_TYPE_BOOL,
     .default_value = "on",
     .description = "the volfile grammar needs one option or subvolume; the tree is always read-only"},
    {.key = {NULL}},
};

xlator_api_t xlator_api = {
    .init = init,
    .fini = fini,
    .notify = notify,
    .op_version = {GD_OP_VERSION_3_12_0},
    .fops = &fops,
    .cbks = &cbks,
    .options = options,
    .identifier = "fuzzfs",
    .category = GF_TECH_PREVIEW,
};
