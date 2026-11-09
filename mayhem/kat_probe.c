/* Known-answer probe for test.sh: runs real glusterfs library code on fixed inputs and prints the
 * results, which test.sh compares against the expected values. Built with the project's NORMAL flags. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>

#include "glusterfs/glusterfs.h"
#include "glusterfs/dict.h"
#include "glusterfs/common-utils.h"
#include "xdr-common.h"
#include "xdr-rpc.h"
#include "gf_fuzz_init.h"

static void
put32(uint8_t *p, uint32_t v)
{
    p[0] = v >> 24;
    p[1] = v >> 16;
    p[2] = v >> 8;
    p[3] = v;
}

static void
kat_strings(void)
{
    uint64_t u64 = 0;
    int64_t i64 = 0;
    int i = 0;
    int ret;
    gf_boolean_t b = _gf_false;
    gf_boolean_t pct = _gf_false;
    double d = 0;
    char path[64];

    ret = gf_string2bytesize_uint64("1GB", &u64);
    printf("bytesize 1GB=%d:%llu\n", ret, (unsigned long long)u64);
    ret = gf_string2bytesize_uint64("512KB", &u64);
    printf("bytesize 512KB=%d:%llu\n", ret, (unsigned long long)u64);
    printf("bytesize bogus=%d\n", gf_string2bytesize_int64("12XB", &i64));
    ret = gf_string2int("0x1f", &i);
    printf("int 0x1f=%d:%d\n", ret, i);
    ret = gf_string2boolean("on", &b);
    printf("bool on=%d:%d\n", ret, (int)b);
    ret = gf_string2boolean("Disable", &b);
    printf("bool Disable=%d:%d\n", ret, (int)b);
    printf("bool maybe=%d\n", gf_string2boolean("maybe", &b));
    ret = gf_string2percent_or_bytesize("25%", &d, &pct);
    printf("pct 25%%=%d:%.1f:%d\n", ret, d, (int)pct);
    printf("ipnet=%d,%d\n", (int)gf_is_ip_in_net("10.0.0.0/8", "10.1.2.3"),
           (int)gf_is_ip_in_net("10.0.0.0/8", "11.1.2.3"));
    printf("ipv4=%d,%d\n", valid_ipv4_address("192.168.1.10", 12, _gf_false),
           valid_ipv4_address("192.168.1.300", 13, _gf_false));
    printf("host=%d,%d\n", valid_host_name("gluster-1.example.com", 21),
           valid_host_name("-bad.example.com", 16));
    snprintf(path, sizeof(path), "%s", "/a//b/c/");
    ret = gf_canonicalize_path(path);
    printf("canon=%d:%s\n", ret, path);
}

static void
kat_dict(void)
{
    dict_t *d = dict_new();
    dict_t *back = dict_new();
    char *buf = NULL;
    u_int len = 0;
    char *str = NULL;
    int32_t i32 = 0;
    uint64_t u64 = 0;
    uint32_t j;
    int ret;

    ret = dict_set_str(d, "volname", "vol0");
    ret |= dict_set_int32(d, "count", 7);
    ret |= dict_set_uint64(d, "size", 0x0102030405060708ULL);
    printf("dict set=%d\n", ret);
    printf("dict count=%d\n", d->count);
    printf("dict ser=%d\n", dict_allocate_and_serialize(d, &buf, &len));
    printf("dict serlen=%u hdr=", len);
    for (j = 0; j < 4 && j < len; j++)
        printf("%02x", (uint8_t)buf[j]);
    printf("\n");
    printf("dict unser=%d\n", dict_unserialize(buf, (int32_t)len, &back));
    printf("dict back count=%d\n", back->count);
    ret = dict_get_str(back, "volname", &str);
    printf("dict get_str=%d:%s\n", ret, str ? str : "(null)");
    ret = dict_get_int32(back, "count", &i32);
    printf("dict get_int32=%d:%d\n", ret, i32);
    ret = dict_get_uint64(back, "size", &u64);
    printf("dict get_uint64=%d:%llx\n", ret, (unsigned long long)u64);
    printf("dict missing=%d\n", dict_get_int32(back, "nokey", &i32));
    GF_FREE(buf);
    dict_unref(d);
    dict_unref(back);
}

static void
kat_rpc(void)
{
    uint8_t m[44];
    struct rpc_msg msg;
    struct iovec payload;
    char cred[GF_MAX_AUTH_BYTES];
    char verf[GF_MAX_AUTH_BYTES];
    int ret;

    memset(m, 0, sizeof(m));
    put32(m + 0, 0x12345678); /* xid */
    put32(m + 4, 0);          /* CALL */
    put32(m + 8, 2);          /* rpc version */
    put32(m + 12, 1238433);   /* GlusterFS handshake program */
    put32(m + 16, 330);       /* version */
    put32(m + 20, 2);         /* procedure */
    /* cred and verf: AUTH_NONE with no body (zeros) */
    put32(m + 40, 0xdeadbeef); /* trailing payload */

    ret = xdr_to_rpc_call((char *)m, sizeof(m), &msg, &payload, cred, verf);
    printf("rpc call=%d xid=%x prog=%u vers=%u proc=%u\n", ret,
           (unsigned)msg.rm_xid, (unsigned)msg.ru.RM_cmb.cb_prog,
           (unsigned)msg.ru.RM_cmb.cb_vers, (unsigned)msg.ru.RM_cmb.cb_proc);
    printf("rpc payload=%zu\n", payload.iov_len);
    ret = xdr_to_rpc_call((char *)m, 10, &msg, &payload, cred, verf);
    printf("rpc truncated=%d\n", ret);
}

int
main(void)
{
    if (gf_fuzz_init() != 0) {
        fprintf(stderr, "ctx init failed\n");
        return 2;
    }
    kat_strings();
    kat_dict();
    kat_rpc();
    return 0;
}
