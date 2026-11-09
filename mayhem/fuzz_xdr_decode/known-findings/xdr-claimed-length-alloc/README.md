# libtirpc allocates the claimed length before checking the input (not a glusterfs bug)

The rpcgen decoders (`xdr_gfx_value`, `xdr_gfx_dict_pair`, ...) call libtirpc's `xdr_bytes`/`xdr_string`,
which `calloc()` the length read from the wire (up to 4 GiB) before looking at how many input bytes remain.
A 4-byte length field is enough to make libFuzzer's default 2 GiB `-malloc_limit_mb` report an
`out-of-memory` defect with `calloc` <- `xdr_bytes` as the top frames. The allocation is then released
when the decode fails on the short input, so it is an allocator artifact and not memory corruption.

The Mayhemfile raises `-malloc_limit_mb` to 8192 so these allocations (at most one per input, since the
decode stops at the first short read) reach ASan's allocator, which serves them lazily, instead of being
reported. Nothing in the harness skips or filters inputs.
