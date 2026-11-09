/* Fuzzes glusterfs' option-value and address string parsers (volume set / volfile options, auth.allow). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "glusterfs/glusterfs.h"
#include "glusterfs/common-utils.h"
#include "gf_fuzz_init.h"

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return gf_fuzz_init() ? 1 : 0;
}

#define IGN(x)                                                                 \
    do {                                                                       \
        long long rc_ = (long long)(x);                                        \
        (void)rc_;                                                             \
    } while (0)

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *s, *t;
    size_t split;
    int len;

    if (size < 1 || size > 4096)
        return -1;

    s = malloc(size + 1);
    if (!s)
        return -1;
    memcpy(s, data, size);
    s[size] = '\0';

    {
        long l;
        unsigned long ul;
        int i;
        unsigned int ui;
        double d;
        long long ll;
        unsigned long long ull;
        int8_t i8;
        int16_t i16;
        int32_t i32;
        int64_t i64;
        uint8_t u8;
        uint16_t u16;
        uint32_t u32;
        uint64_t u64;
        gf_boolean_t b;
        gf_boolean_t pct;
        time_t tm;

        IGN(gf_string2long(s, &l));
        IGN(gf_string2ulong(s, &ul));
        IGN(gf_string2int(s, &i));
        IGN(gf_string2uint(s, &ui));
        IGN(gf_string2double(s, &d));
        IGN(gf_string2longlong(s, &ll));
        IGN(gf_string2ulonglong(s, &ull));
        IGN(gf_string2int8(s, &i8));
        IGN(gf_string2int16(s, &i16));
        IGN(gf_string2int32(s, &i32));
        IGN(gf_string2int64(s, &i64));
        IGN(gf_string2uint8(s, &u8));
        IGN(gf_string2uint16(s, &u16));
        IGN(gf_string2uint32(s, &u32));
        IGN(gf_string2uint64(s, &u64));
        IGN(gf_string2ulong_base10(s, &ul));
        IGN(gf_string2uint_base10(s, &ui));
        IGN(gf_string2uint8_base10(s, &u8));
        IGN(gf_string2uint16_base10(s, &u16));
        IGN(gf_string2uint32_base10(s, &u32));
        IGN(gf_string2uint64_base10(s, &u64));
        IGN(gf_string2bytesize_uint64(s, &u64));
        IGN(gf_string2bytesize_int64(s, &i64));
        IGN(gf_string2percent_or_bytesize(s, &d, &pct));
        IGN(gf_string2boolean(s, &b));
        IGN(gf_strn2boolean(s, (int)size, &b));
        IGN(gf_string2percent(s, &d));
        IGN(gf_string2time(s, &tm));
    }

    /* every in-tree caller passes strlen() as the length */
    len = (int)strlen(s);
    IGN(valid_host_name(s, len));
    IGN(valid_ipv4_address(s, len, _gf_false));
    IGN(valid_ipv4_address(s, len, _gf_true));
    IGN(valid_ipv6_address(s, len, _gf_false));
    IGN(valid_ipv6_address(s, len, _gf_true));
    IGN(valid_internet_address(s, _gf_false, _gf_false));
    IGN(valid_internet_address(s, _gf_true, _gf_true));

    /* "network ip": split at the first space/newline-free midpoint for the CIDR matcher */
    split = size / 2;
    t = s + split;
    {
        char saved = s[split];
        s[split] = '\0';
        IGN(gf_is_ip_in_net(s, t));
        s[split] = saved;
    }

    {
        char *path = gf_strdup(s);
        if (path) {
            IGN(gf_canonicalize_path(path));
            GF_FREE(path);
        }
    }

    free(s);
    return 0;
}
