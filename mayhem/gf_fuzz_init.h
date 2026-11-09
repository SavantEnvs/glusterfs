/* Minimal in-process glusterfs runtime for the harnesses: a context with the dict/log pools and
 * logging off, with no threads, event pool or log file (the same pieces libgfapi sets up first). */
#ifndef GF_FUZZ_INIT_H
#define GF_FUZZ_INIT_H

#include "glusterfs/glusterfs.h"
#include "glusterfs/globals.h"
#include "glusterfs/logging.h"
#include "glusterfs/mem-pool.h"
#include "glusterfs/xlator.h"
#include "glusterfs/dict.h"

#define GF_FUZZ_DICT_POOL 4096
#define GF_FUZZ_DATA_POOL (GF_FUZZ_DICT_POOL * 4)
#define GF_FUZZ_LOGBUF_POOL 256

static inline int
gf_fuzz_init(void)
{
    glusterfs_ctx_t *ctx = NULL;

    mem_pools_init();

    /* plain malloc/free, so ASan sees every allocation (no accounting headers) */
    gf_global_mem_acct_enable_set(0);

    ctx = glusterfs_ctx_new();
    if (!ctx)
        return -1;
    if (glusterfs_globals_init(ctx))
        return -1;

    THIS->ctx = ctx;
    THIS->name = "glusterfs-fuzz";
    ctx->log.loglevel = GF_LOG_NONE;
    ctx->page_size = 128 * GF_UNIT_KB;

    ctx->dict_pool = mem_pool_new(dict_t, GF_FUZZ_DICT_POOL);
    ctx->dict_data_pool = mem_pool_new(data_t, GF_FUZZ_DATA_POOL);
    ctx->logbuf_pool = mem_pool_new(log_buf_t, GF_FUZZ_LOGBUF_POOL);
    if (!ctx->dict_pool || !ctx->dict_data_pool || !ctx->logbuf_pool)
        return -1;
    return 0;
}

#endif
