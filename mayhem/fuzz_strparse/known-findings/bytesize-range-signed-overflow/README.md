# gf_string2bytesize_range: signed overflow in the range check

`libglusterfs/src/common-utils.c`: for an integer with a `KB`..`PB` suffix, `gf_string2bytesize_range()`
multiplies `int_value *= unit` on an `int64_t`, which wraps negative for a large value, and then tests
`(max - int_value) < 0`. With a negative `int_value` that subtraction itself overflows (`max` is up to
`INT64_MAX`), which is undefined behaviour. The check only rejects the value when the compiler happens to wrap.

Reproducer `repro` (`9223372036854775807KB`): run `/mayhem/fuzz_strparse-standalone repro` for the UBSan
report `signed integer overflow: 9223372036854775807 - -1024 cannot be represented in type 'int64_t'`
at `common-utils.c:1508`.

Impact: any option parsed with `gf_string2bytesize_*` (volume options such as `performance.cache-size`).
No memory corruption; the result is a wrong or luckily-rejected size.

Fix: reject before multiplying, `if (int_value > max / unit) { errno = ERANGE; return -1; }`, and make the
final check `int_value > max`.
