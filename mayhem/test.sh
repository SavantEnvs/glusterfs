#!/usr/bin/env bash
# mayhem/test.sh — runs the known-answer probe that build.sh linked against glusterfs' real
# libglusterfs/libgfxdr/libgfrpc (normal flags) and compares each output line with its expected value.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

PROBE="$SRC/mayhem/build/kat_probe"
if [ ! -x "$PROBE" ]; then
  echo "missing $PROBE — mayhem/build.sh did not build it" >&2
  emit_ctrf "glusterfs-kat" 0 1
  exit 1
fi

EXPECTED=$(cat <<'KAT'
bytesize 1GB=0:1073741824
bytesize 512KB=0:524288
bytesize bogus=-1
int 0x1f=0:31
bool on=0:1
bool Disable=0:0
bool maybe=-1
pct 25%=0:25.0:1
ipnet=1,0
ipv4=1,0
host=1,0
canon=0:/a/b/c
dict set=0
dict count=3
dict ser=0
dict serlen=72 hdr=00000003
dict unser=0
dict back count=3
dict get_str=0:vol0
dict get_int32=0:7
dict get_uint64=0:102030405060708
dict missing=-2
rpc call=0 xid=12345678 prog=1238433 vers=330 proc=2
rpc payload=4
rpc truncated=-1
KAT
)

ACTUAL=$("$PROBE" 2>/dev/null)
rc=$?

passed=0
failed=0
while IFS= read -r want; do
  if grep -qxF -- "$want" <<<"$ACTUAL"; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: expected line not produced: $want" >&2
  fi
done <<<"$EXPECTED"

if [ "$rc" -ne 0 ]; then
  failed=$((failed + 1))
  echo "FAIL: probe exited $rc" >&2
fi

emit_ctrf "glusterfs-kat" "$passed" "$failed"
