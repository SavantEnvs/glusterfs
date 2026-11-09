/* Fuzz the dict wire format: dict_unserialize() (the GFS dict blob that every
 * brick/glusterd/client RPC carries), the typed getters over its pairs and a
 * serialize round trip. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "glusterfs/dict.h"
#include "glusterfs/iatt.h"
#include "gf_fuzz_init.h"

#define IGN(x)                                                                 \
    do {                                                                       \
        int rc_ = (int)(x);                                                    \
        (void)rc_;                                                             \
    } while (0)

static int
probe_pair(dict_t *d, char *key, data_t *value, void *unused)
{
    int8_t i8;
    int16_t i16;
    int32_t i32;
    int64_t i64;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;
    double dbl;
    char *str = NULL;
    void *ptr = NULL;
    uuid_t gfid;
    struct iatt iatt;
    struct mdata_iatt mdata;

    IGN(dict_get_int8(d, key, &i8));
    IGN(dict_get_int16(d, key, &i16));
    IGN(dict_get_int32(d, key, &i32));
    IGN(dict_get_int64(d, key, &i64));
    IGN(dict_get_uint16(d, key, &u16));
    IGN(dict_get_uint32(d, key, &u32));
    IGN(dict_get_uint64(d, key, &u64));
    IGN(dict_get_double(d, key, &dbl));
    IGN(dict_get_str(d, key, &str));
    IGN(dict_get_bin(d, key, &ptr));
    IGN(dict_get_gfuuid(d, key, &gfid));
    IGN(dict_get_iatt(d, key, &iatt));
    IGN(dict_get_mdata(d, key, &mdata));
    if (value && value->data && value->len > 0) {
        (void)data_to_str(value);
        (void)data_to_int64(value);
        (void)data_to_uint64(value);
    }
    return 0;
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return gf_fuzz_init() ? 1 : 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *buf = NULL;
    dict_t *dict = NULL;
    dict_t *again = NULL;
    char *out = NULL;
    u_int outlen = 0;

    if (size == 0 || size > (1u << 20))
        return -1;

    buf = malloc(size);
    if (!buf)
        return 0;
    memcpy(buf, data, size);

    dict = dict_new();
    if (!dict) {
        free(buf);
        return 0;
    }

    if (dict_unserialize(buf, (int32_t)size, &dict) == 0) {
        dict_foreach(dict, probe_pair, NULL);

        if (dict_allocate_and_serialize(dict, &out, &outlen) == 0 && out) {
            again = dict_new();
            if (again) {
                if (dict_unserialize(out, (int32_t)outlen, &again) == 0)
                    dict_foreach(again, probe_pair, NULL);
                dict_unref(again);
            }
            GF_FREE(out);
        }
    }

    dict_unref(dict);
    free(buf);
    return 0;
}
