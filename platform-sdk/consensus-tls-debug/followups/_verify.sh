#!/bin/bash
# Verification script: runs each benchmarked configuration with --verify and
# captures the negotiated protocol / named group / signature scheme.
#
# BCJSSE configurations dump FINE-level logs to stderr; SunJSSE configurations
# dump javax.net.debug=ssl:handshake to stderr. Both formats grep for the same
# tokens.

set -e
cd /Users/maxi/Hashgraph/code/1/hedera-services
OUT=platform-sdk/consensus-tls-debug/followups/_verify.txt
> "$OUT"

verify() {
    local label=$1; shift
    {
        echo "============================================================"
        echo "=== $label"
        echo "    args: $*"
        echo "============================================================"
        ./gradlew :consensus-tls-debug:run --args="$* --verify" --console=plain --quiet 2>&1
        echo ""
    } >> "$OUT"
}

verify "A0.SunJSSE.classical.noAccp"  --sunjsse-bench --no-accp
verify "A0.SunJSSE.classical.accp"    --sunjsse-bench

verify "A.classical.noAccp"  --hybrid --no-accp
verify "A.classical.accp"    --hybrid
verify "A.hybrid.noAccp"     --hybrid --mlkem --no-accp
verify "A.hybrid.accp"       --hybrid --mlkem
verify "A.pure.noAccp"       --hybrid --mlkem --pure --no-accp
verify "A.pure.accp"         --hybrid --mlkem --pure

verify "B.classical.noAccp"  --hybrid --mldsa --no-accp
verify "B.classical.accp"    --hybrid --mldsa
verify "B.hybrid.noAccp"     --hybrid --mldsa --mlkem --no-accp
verify "B.hybrid.accp"       --hybrid --mldsa --mlkem
verify "B.pure.noAccp"       --hybrid --mldsa --mlkem --pure --no-accp
verify "B.pure.accp"         --hybrid --mldsa --mlkem --pure

echo "VERIFY COMPLETE" >> "$OUT"