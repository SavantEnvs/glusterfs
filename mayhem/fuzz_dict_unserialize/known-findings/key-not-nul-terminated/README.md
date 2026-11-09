# dict_unserialize stores a key that is not NUL-terminated

`libglusterfs/src/dict.c`: `dict_unserialize()` takes the key as `buf[0..keylen]` and passes it to
`dict_addn()`, which copies `key_len + 1` bytes (`dict_set_lk`, `memcpy(pair->key, key, key_len + 1)`).
The byte after the key is the wire format's terminator, but it is never checked to be `\0`. A peer
that sends `AB` for a key of length 1 gets a stored key `"AB"` with no terminator inside the
`key_len + 1` allocation, so the next `strcmp(pair->key, ...)` (`dict_lookup_common`) reads past the heap
object. A key that ends exactly at the end of the buffer also makes `buf += keylen + 1` step one
byte past the validated range.

Reproducer `repro` (`count=1, keylen=1, vallen=0, "AB"`): run
`/mayhem/fuzz_dict_unserialize-standalone repro` for the ASan heap-buffer-overflow in `strcmp`.

Fix: reject the pair unless `buf[keylen] == '\0'` and `buf + keylen + 1 <= orig_buf + size`.
