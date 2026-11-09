/* Fuzzes the XDR decoders glusterfs runs on every network message: the RPC call/reply/AUTH_UNIX
 * decoders of rpc-lib (entries 0-2), then the rpcgen decoders of every wire type (glusterfs4,
 * glusterd, cli, portmap, changelog, rpc-common). xdr_table.inc is generated from the built xdr headers by build.sh: one
 * XDR_TYPE(<xdr proc name>, <C type>) per decoder. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <rpc/rpc.h>

#include "glusterfs/glusterfs.h"
#include "glusterfs/dict.h"
#include "glusterfs/compat-errno.h"
#include "xdr-common.h"
#include "xdr-generic.h"
#include "xdr-rpc.h"
#include "xdr-rpcclnt.h"
#include "changelog-xdr.h"
#include "cli1-xdr.h"
#include "glusterd1-xdr.h"
#include "glusterfs4-xdr.h"
#include "portmap-xdr.h"
#include "rpc-common-xdr.h"
#include "gf_fuzz_init.h"
#include "glusterfs/stack.h"

typedef void (*decode_fn)(char *buf, size_t len);

static void
run_rpc_call(char *buf, size_t len)
{
    struct rpc_msg msg;
    struct iovec payload;
    char cred[GF_MAX_AUTH_BYTES];
    char verf[GF_MAX_AUTH_BYTES];

    memset(&payload, 0, sizeof(payload));
    if (xdr_to_rpc_call(buf, len, &msg, &payload, cred, verf) == 0 &&
        payload.iov_len > len)
        abort();
}

static void
run_rpc_reply(char *buf, size_t len)
{
    struct rpc_msg msg;
    struct iovec payload;
    char verf[GF_MAX_AUTH_BYTES];

    memset(&payload, 0, sizeof(payload));
    if (xdr_to_rpc_reply(buf, len, &msg, &payload, verf) == 0 &&
        payload.iov_len > len)
        abort();
}

static void
run_auth_unix(char *buf, size_t len)
{
    struct authunix_parms aup;
    char machname[MAX_MACHINE_NAME];
    gid_t gids[SMALL_GROUP_COUNT];

    memset(&aup, 0, sizeof(aup));
    if (xdr_to_auth_unix_cred(buf, (int)len, &aup, machname, gids) == 0 &&
        aup.aup_len > SMALL_GROUP_COUNT)
        abort();
}

#define XDR_TYPE(name, type)                                                   \
    static void run_##name(char *buf, size_t len)                              \
    {                                                                          \
        XDR xdr;                                                               \
        type obj;                                                              \
        memset(&obj, 0, sizeof(obj));                                          \
        xdrmem_create(&xdr, buf, len, XDR_DECODE);                             \
        (void)xdr_##name(&xdr, &obj);                                          \
        xdr_free((xdrproc_t)xdr_##name, (char *)&obj);                         \
    }
#include "xdr_table.inc"
#undef XDR_TYPE

#define XDR_TYPE(name, type) run_##name,
static const decode_fn decoders[] = {
    run_rpc_call, run_rpc_reply, run_auth_unix,
#include "xdr_table.inc"
};
#undef XDR_TYPE

#define N_DECODERS (sizeof(decoders) / sizeof(decoders[0]))

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return gf_fuzz_init() ? 1 : 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *buf;
    uint16_t sel;

    if (size < 3 || size > (1u << 16))
        return -1;

    memcpy(&sel, data, sizeof(sel));
    size -= 2;
    buf = malloc(size);
    if (!buf)
        return -1;
    memcpy(buf, data + 2, size);

    decoders[sel % N_DECODERS](buf, size);

    free(buf);
    return 0;
}
