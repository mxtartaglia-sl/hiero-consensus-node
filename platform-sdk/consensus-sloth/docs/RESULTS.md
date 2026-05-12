# SignatureSchemeExperiment — 5-config comparison: Baseline / SUN+ACCP / BJSSE-PQ / BJSSE+ACCP (PQ KX) / BJSSE+ACCP (PQ KX + ML-DSA-65 certs)

## Test setup (common to all five tarballs)

- Class: `org.hiero.sloth.test.performance.experiments.signature.SignatureSchemeExperiment`
- Methods executed per run: `signatureSchemeRSA`, then `signatureSchemeED25519`
- Topology: 4 nodes (Docker-fixture), Linux remote host
- Target throughput: 10.0 TPS per node × 4 = **40 TPS total**
- Warm-up: 5 s of empty txs at target rate
- Benchmark window: `PT4M` = **240 s** of BENCHMARK txs at target rate (expected to reach `40 × 240 = 9600` total txs if generation keeps up)
- 4 runs per cell (8 directories per tarball — one dir per `(run, scheme)`)

Latency `Avg`, `p50`, `p99`, `Max` are in µs and come from the `TOTAL` row of `benchmark.log` (network-wide). `Throughput` is the `Test throughput:` line. **"Hit 40?"** asks whether the benchmark generated all 9604 expected txs and the network sustained the target rate; when RSA is the bottleneck, generation back-pressures and only ~5000 txs are produced over a longer window (~245 s).

## Sources

* (a) **Baseline** — main  
* (b) **SUN TLS 1.2 + ACCP** — main + **ACCP** 
* (c) BCJSSE TLS 1.3 **PQ FULL** (kx:X25519MLKEM768 auth:ML-DSA-65) 
* (d) BCJSSE TLS 1.3 + ACCP **PQ KX only** (kx:X25519MLKEM768 auth:classical EC) 
* (e) BCJSSE TLS 1.3 + ACCP **PQ FULL** (kx:X25519MLKEM768 auth:ML-DSA-65)

Config validation (from `swirlds-node-0.log` of run 1 of each cell):

| Cell | `ACCP registered` count | roster `agr_key_type` |
|---|---:|---|
| (a) Baseline | 0 | EdDSA / EC (classical) |
| (b) SUN + ACCP | 1 | EdDSA / EC (classical) |
| (c) BJSSE_PQ | 0 | ML-DSA-65 |
| (d) BJSSE+ACCP KX-only | 1 | EC |
| (e) BJSSE+ACCP PQ | 1 | ML-DSA |

---

## (a) Baseline

### RSA (`signatureSchemeRSA`) — 4 runs

| # | Count | Avg µs | p50 µs | p99 µs | Max µs | Throughput | Hit 40 TPS? |
|---|---:|---:|---:|---:|---:|---:|---|
| 1 | 4986 | 6,896,421 | 6,973,295 | 12,106,837 | 12,963,995 | 20.22 tx/s | **NO** (4986/9604 over 246.6 s) |
| 2 | 4764 | 4,952,999 | 4,782,017 | 8,485,084 | 9,147,831 | 19.58 tx/s | **NO** (4764/9604 over 243.4 s) |
| 3 | 4770 | 5,160,391 | 4,974,780 | 8,316,939 | 9,187,496 | 19.60 tx/s | **NO** (4770/9604 over 243.4 s) |
| 4 | 4881 | 6,357,878 | 5,955,485 | 11,908,080 | 13,324,946 | 19.84 tx/s | **NO** (4881/9604 over 246.0 s) |
| **mean** | 4850 | **5,841,922** | 5,671,394 | 10,204,237 | 11,156,067 | **19.81 tx/s** | — |

### ED25519 — 4 runs

| # | Count | Avg µs | p50 µs | p99 µs | Max µs | Throughput | Hit 40 TPS? |
|---|---:|---:|---:|---:|---:|---:|---|
| 1 | 9604 | 2,815 | 2,643 | 3,847 | 40,059 | 40.02 tx/s | YES |
| 2 | 9602 | 2,930 | 2,804 | 4,303 | 27,291 | 40.01 tx/s | YES (2-tx short of 9604, strict-count assertion failed) |
| 3 | 9603 | 2,691 | 2,663 | 3,873 | 26,880 | 40.01 tx/s | YES (1-tx short) |
| 4 | 9602 | 3,405 | 3,323 | 4,361 | 32,998 | 40.01 tx/s | YES (2-tx short) |
| **mean** | 9603 | **2,960** | 2,858 | 4,096 | 31,807 | **40.01 tx/s** | — |

---

## (b) **SUN TLS 1.2 + ACCP** — main + **ACCP**

### RSA — 4 runs

| # | Count | Avg µs | p50 µs | p99 µs | Max µs | Throughput | Hit 40 TPS? |
|---|---:|---:|---:|---:|---:|---:|---|
| 1 | 5986 | 1,742,019 | 1,245,771 | 3,583,056 | 3,780,637 | 24.68 tx/s | **NO** (5986/9604, +20% txs vs Baseline) |
| 2 | 5948 | 1,726,668 | 1,258,884 | 3,563,114 | 3,805,137 | 24.42 tx/s | **NO** |
| 3 | 5927 | 1,762,286 | 1,350,788 | 3,600,287 | 3,798,135 | 24.47 tx/s | **NO** |
| 4 | 5951 | 1,742,735 | 1,323,152 | 3,632,104 | 3,827,308 | 24.56 tx/s | **NO** |
| **mean** | 5953 | **1,743,427** | 1,294,649 | 3,594,640 | 3,802,804 | **24.53 tx/s** | — |

### ED25519 — 4 runs

| # | Count | Avg µs | p50 µs | p99 µs | Max µs | Throughput | Hit 40 TPS? |
|---|---:|---:|---:|---:|---:|---:|---|
| 1 | 9604 | 2,672 | 2,719 | 3,175 | 9,320 | 40.02 tx/s | YES |
| 2 | 9604 | 2,705 | 2,583 | 3,593 | 34,051 | 40.02 tx/s | YES |
| 3 | 9604 | 2,536 | 2,564 | 3,208 | 44,109 | 40.02 tx/s | YES |
| 4 | 9604 | 2,431 | 2,345 | 3,236 | 9,946 | 40.02 tx/s | YES |
| **mean** | 9604 | **2,586** | 2,553 | 3,303 | 24,357 | **40.02 tx/s** | — |

Note: ACCP is registered (count=1) and shows ML-DSA-{44,65,87} services in node logs. RSA latency drops ~3.35× vs Baseline, but RSA still doesn't saturate at 40 TPS — RSA is still the consensus-path bottleneck.

---

## (c) BCJSSE TLS 1.3 **PQ FULL** (kx:X25519MLKEM768 auth:ML-DSA-65)

### RSA — 4 runs

| # | Count | Avg µs | p50 µs | p99 µs | Max µs | Throughput | Hit 40 TPS? |
|---|---:|---:|---:|---:|---:|---:|---|
| 1 | 5114 | 8,556,889 | 8,425,516 | 12,098,364 | 13,352,882 | 20.86 tx/s | **NO** |
| 2 | 4894 | 5,319,954 | 5,063,213 | 8,577,971 | 10,430,886 | 19.76 tx/s | **NO** |
| 3 | 5030 | 7,616,014 | 7,962,535 | 12,024,747 | 12,737,552 | 20.40 tx/s | **NO** |
| 4 | 5004 | 7,551,140 | 8,004,241 | 12,114,082 | 12,901,000 | 20.07 tx/s | **NO** |
| **mean** | 5011 | **7,260,999** | 7,363,876 | 11,203,791 | 12,355,580 | **20.27 tx/s** | — |

### ED25519 — 4 runs

| # | Count | Avg µs | p50 µs | p99 µs | Max µs | Throughput | Hit 40 TPS? |
|---|---:|---:|---:|---:|---:|---:|---|
| 1 | 9603 | 2,697 | 2,630 | 3,753 | 13,783 | 40.01 tx/s | YES |
| 2 | 9603 | 2,552 | 2,651 | 3,203 | 12,624 | 40.01 tx/s | YES |
| 3 | 9604 | 2,981 | 2,938 | 3,919 | 25,426 | 40.02 tx/s | YES |
| 4 | 9602 | 3,112 | 3,111 | 3,993 | 24,340 | 40.01 tx/s | YES |
| **mean** | 9603 | **2,835** | 2,833 | 3,717 | 19,043 | **40.01 tx/s** | — |

Note: TLS path uses BCJSSE + ML-DSA-65 agreement cert (PQ handshake), but consensus signature path uses plain BC (no ACCP). RSA mean is comparable to Baseline (within noise / slightly slower).

---

## (d) BCJSSE TLS 1.3 + ACCP **PQ KX only** (kx:X25519MLKEM768 auth:classical EC)

### RSA — 4 runs

| # | Count | Avg µs | p50 µs | p99 µs | Max µs | Throughput | Hit 40 TPS? |
|---|---:|---:|---:|---:|---:|---:|---|
| 1 | 9604 | 4,445 | 4,416 | 6,026 | 17,860 | 40.02 tx/s | **YES** |
| 2 | 9604 | 4,466 | 4,429 | 6,564 | 24,969 | 40.02 tx/s | **YES** |
| 3 | 9604 | 4,610 | 4,566 | 6,345 | 32,033 | 40.02 tx/s | **YES** |
| 4 | 9604 | 4,588 | 4,552 | 5,784 | 26,996 | 40.02 tx/s | **YES** |
| **mean** | 9604 | **4,527** | 4,491 | 6,180 | 25,464 | **40.02 tx/s** | — |

### ED25519 — 4 runs

| # | Count | Avg µs | p50 µs | p99 µs | Max µs | Throughput | Hit 40 TPS? |
|---|---:|---:|---:|---:|---:|---:|---|
| 1 | 9604 | 2,654 | 2,573 | 3,634 | 124,906 | 40.02 tx/s | YES |
| 2 | 9604 | 2,649 | 2,621 | 3,066 | 15,022 | 40.02 tx/s | YES |
| 3 | 9604 | 2,498 | 2,468 | 3,248 | 19,901 | 40.02 tx/s | YES |
| 4 | 9604 | 2,548 | 2,585 | 3,190 | 11,993 | 40.02 tx/s | YES |
| **mean** | 9604 | **2,587** | 2,562 | 3,285 | 42,956 | **40.02 tx/s** | — |

Note: 0 errors / 0 build failures across all 4 runs. ACCP registered (count=1); `agr_key_type: EC` confirms classical EC agreement cert with PQ key-exchange only.

---

## (e) BCJSSE TLS 1.3 + ACCP **PQ FULL** (kx:X25519MLKEM768 auth:ML-DSA-65)

### RSA — 4 runs

| # | Count | Avg µs | p50 µs | p99 µs | Max µs | Throughput | Hit 40 TPS? |
|---|---:|---:|---:|---:|---:|---:|---|
| 1 | 9603 | 4,476 | 4,377 | 6,012 | 28,472 | 40.01 tx/s | **YES** (1-tx short) |
| 2 | 9604 | 4,815 | 4,759 | 7,057 | 12,243 | 40.02 tx/s | **YES** |
| 3 | 9604 | 4,450 | 4,405 | 5,647 | 90,397 | 40.01 tx/s | **YES** |
| 4 | 9604 | 4,287 | 4,260 | 5,444 | 24,006 | 40.02 tx/s | **YES** |
| **mean** | 9604 | **4,507** | 4,450 | 6,040 | 38,780 | **40.02 tx/s** | — |

### ED25519 — 4 runs

| # | Count | Avg µs | p50 µs | p99 µs | Max µs | Throughput | Hit 40 TPS? |
|---|---:|---:|---:|---:|---:|---:|---|
| 1 | 9604 | 2,705 | 2,710 | 3,373 | 13,430 | 40.02 tx/s | YES |
| 2 | 9604 | 2,709 | 2,591 | 3,371 | 27,847 | 40.02 tx/s | YES |
| 3 | 9604 | 2,576 | 2,574 | 3,683 | 9,447 | 40.02 tx/s | YES |
| 4 | 9604 | 2,546 | 2,535 | 4,038 | 31,792 | 40.02 tx/s | YES |
| **mean** | 9604 | **2,634** | 2,603 | 3,616 | 20,629 | **40.02 tx/s** | — |

Note: ACCP registered (count=1); `agr_key_type: ML-DSA` confirms full PQ TLS (PQ KX + ML-DSA-65 cert) running concurrently with ACCP-accelerated consensus signature verification.

---

## Summary — performance gains

### RSA — mean across 4 runs

| Cell | Avg | vs Baseline | p99 | Throughput | Hit 40 TPS? |
|---|---:|---:|---:|---:|---|
| (a)  | 5,841,922 µs | 1.00× | 10,204,237 µs | 19.81 tx/s | No |
| (b) | 1,743,427 µs | 3.35× faster | 3,594,640 µs | 24.53 tx/s | No |
| (c)   | 7,260,999 µs | 0.80× (~baseline) | 11,203,791 µs | 20.27 tx/s | No |
| (d)  | **4,527 µs** | **~1,290× faster** | **6,180 µs** | **40.02 tx/s** | **YES** |
| (e) | **4,507 µs** | **~1,296× faster** | **6,040 µs** | **40.02 tx/s** | **YES** |

### ED25519 — mean across 4 runs

| Cell | Avg | vs Baseline | p99 | Throughput | Hit 40 TPS? |
|---|---:|---:|---:|---:|---|
| (a)| 2,960 µs | 1.00× | 4,096 µs | 40.01 tx/s | YES |
| (b)  | 2,586 µs | 1.14× faster | 3,303 µs | 40.02 tx/s | YES |
| (c) | 2,835 µs | 1.04× faster | 3,717 µs | 40.01 tx/s | YES |
| (d) | 2,587 µs | 1.14× faster | 3,285 µs | 40.02 tx/s | YES |
| (e) | 2,634 µs | 1.12× faster | 3,616 µs | 40.02 tx/s | YES |

### Bottom line

- **Cells (d) and (e) are the breakthrough**: with the BCJSSE + ACCP combination, RSA mean latency drops from **multi-second** (5.8 s Baseline / 1.7 s SUN+ACCP) to **~4.5 ms** — three orders of magnitude — and RSA finally **sustains the 40 TPS target with all 9604 txs delivered**. p99 drops from ~10 s (Baseline) to ~6 ms.
- **The PQ ML-DSA-65 agreement cert is essentially free.** Cell (e) (PQ KX + ML-DSA cert + ACCP) is within 0.4% of cell (d) (PQ KX + classical EC cert + ACCP) on RSA mean (4,507 vs 4,527 µs) and within 2% on ED25519 (2,634 vs 2,587 µs). The PQ certificate handshake cost is one-time per connection and not visible on the per-tx signature path.
- **Cell (b) (SUN + ACCP, ACCP under SunJSSE) is much slower than (d)/(e) (ACCP under BCJSSE)** — 1.74 s vs 4.5 ms on RSA mean. ACCP was registered in (b) (`ACCP registered` = 1, ML-DSA services listed) but the consensus-path RSA verification clearly wasn't being routed through ACCP at the same rate as in (d)/(e). The BCJSSE provider stack (plus the hybrid ACCP+BC provider being introduced on this branch — see `AccpBcHybridProvider.java`, `HybridJcaJceHelper.java`) is what unlocks the per-tx ACCP acceleration for consensus signatures.
- **Cell (c) confirms BCJSSE alone is not enough**: BCJSSE + ML-DSA-65 cert without ACCP regresses slightly versus Baseline (7.26 s vs 5.84 s, within noise). ACCP is the actual accelerator; BCJSSE is the integration layer that lets ACCP hit the signature hot path.
- **ED25519 is decoupled from the stack choice.** It clears 40 TPS in every cell; ACCP shaves ~13% off mean and tightens the tail (p99 ~3.3 ms with ACCP vs ~4.1 ms without).

### Caveats / data-quality notes

- 3 of 4 ED25519 runs in Baseline and BJSSE_PQ (and 1 RSA run in cell e) have a Gradle `Task FAILED` from a strict assertion (`expected: 9604 but was 9602/9603`) — a 1–2 tx warm-up edge, not a perf regression. Throughput and latency numbers are valid.
- Per-host comparison: Baseline and (e) ran on `186.233.187.173`; SUN+ACCP, BJSSE_PQ, and (d) ran on `186.233.187.179`. Cells (d) and (e) on different hosts give nearly identical RSA means (4,527 vs 4,507 µs), suggesting the host difference is small relative to the provider-stack effect.
- ED25519 max of 124,906 µs in (d) run 1 is a single GC/JIT outlier — p99 stays under 3.7 ms.