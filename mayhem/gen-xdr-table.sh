#!/bin/bash
# usage: gen-xdr-table.sh <dir with the generated *-xdr.h headers> > xdr_table.inc
set -euo pipefail
cd "$1"
grep -h '^extern  *bool_t xdr_[A-Za-z0-9_]* (XDR \*, [A-Za-z0-9_ ]*\*);' \
    changelog-xdr.h cli1-xdr.h glusterd1-xdr.h glusterfs4-xdr.h portmap-xdr.h rpc-common-xdr.h |
    sed -E 's/^extern +bool_t xdr_([A-Za-z0-9_]+) \(XDR \*, ([A-Za-z0-9_ ]*[A-Za-z0-9_]) *\*\);/XDR_TYPE(\1, \2)/' |
    LC_ALL=C sort -u
