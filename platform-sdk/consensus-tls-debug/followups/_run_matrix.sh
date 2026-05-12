#!/bin/bash
# Benchmark matrix runner. Output: _results.txt (raw), parsed elsewhere.
#
# Matrix A: classical authentication × {classical, hybrid, pure} kx × {no-ACCP, ACCP}
# Matrix B: ML-DSA-65 authentication × same kx × ACCP variants
# Each configuration: 3 trials of 500 iterations + 50 warmup.

set -e
cd /Users/maxi/Hashgraph/code/1/hedera-services
RESULTS=platform-sdk/consensus-tls-debug/followups/_results.txt
> "$RESULTS"

run() {
    local label=$1
    shift
    for trial in 1 2 3; do
        echo "=== $label trial $trial ===" >> "$RESULTS"
        ./gradlew :consensus-tls-debug:run --args="$*" --console=plain --quiet 2>/dev/null \
            | awk '/=== Results ===/,/Throughput/' >> "$RESULTS"
        echo "" >> "$RESULTS"
    done
}

# Matrix A0 — SunJSSE baseline (today's production stack shape, classical only)
run "A0.SunJSSE.classical.noAccp"  --sunjsse-bench --no-accp --iterations=500 --warmup=50
run "A0.SunJSSE.classical.accp"    --sunjsse-bench          --iterations=500 --warmup=50

# Matrix A — classical authentication (RSA-3072 CA + EC-384 agrCert + RSA-PSS) on BCJSSE
run "A.classical.noAccp"  --hybrid --no-accp --iterations=500 --warmup=50
run "A.classical.accp"    --hybrid          --iterations=500 --warmup=50
run "A.hybrid.noAccp"     --hybrid --mlkem --no-accp --iterations=500 --warmup=50
run "A.hybrid.accp"       --hybrid --mlkem          --iterations=500 --warmup=50
run "A.pure.noAccp"       --hybrid --mlkem --pure --no-accp --iterations=500 --warmup=50
run "A.pure.accp"         --hybrid --mlkem --pure          --iterations=500 --warmup=50

# Matrix B — ML-DSA-65 authentication (full PQ auth chain)
run "B.classical.noAccp"  --hybrid --mldsa --no-accp --iterations=500 --warmup=50
run "B.classical.accp"    --hybrid --mldsa          --iterations=500 --warmup=50
run "B.hybrid.noAccp"     --hybrid --mldsa --mlkem --no-accp --iterations=500 --warmup=50
run "B.hybrid.accp"       --hybrid --mldsa --mlkem          --iterations=500 --warmup=50
run "B.pure.noAccp"       --hybrid --mldsa --mlkem --pure --no-accp --iterations=500 --warmup=50
run "B.pure.accp"         --hybrid --mldsa --mlkem --pure          --iterations=500 --warmup=50

echo "MATRIX COMPLETE" >> "$RESULTS"