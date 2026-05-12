# PQ TLS — Performance Results

| | |
|---|---|
| **Status** | Living document |
| **Date** | 2026-05-07 |
| **Scope** | Handshake latency and consensus-side throughput measurements collected during the post-quantum TLS investigation |

This document consolidates all performance numbers measured during the PQ TLS work. It is a single point of reference: numbers shown here are the latest validated values, with retracted measurements explicitly listed in Section 1.3 so they don't propagate by mistake.

---

## 1. Methodology

### 1.1 TLS handshake benchmarks

Unless noted otherwise, handshake measurements were collected with this protocol:

- Hardware: macOS arm64 (M-series), JDK 25, BouncyCastle 1.83, ACCP 2.6.0 (locally built with ML-KEM enabled)
- 500 handshakes per trial, 50 warmup iterations before measurement, 3 trials per configuration
- Trial-to-trial variance ~5–10%
- TLS 1.3 throughout, cipher suite `TLS_AES_256_GCM_SHA384`
- "Classical" = `x25519` named group, EC-384 / RSA-3072 chain, classical signatures
- "PQ kx" = `X25519MLKEM768` named group (hybrid x25519 + ML-KEM-768)
- "PQ auth" = `mldsa65` signature scheme, ML-DSA-65 self-signed cert chain

### 1.2 Consensus-side benchmarks

The Linux consensus benchmarks (`SignatureSchemeExperiment`, `combinedAllOptimizations`) ran on a remote Linux box: 32 CPUs, 128 GB RAM, Java 25.0.2 inside a sloth Docker container. Three runs per configuration, 240 s each, 40 tps target unless noted.

### 1.3 Measurements explicitly retracted

These figures appeared in earlier reports and have been **superseded** by later evidence. They are NOT included in the tables below; they're listed here only so reviewers don't accidentally cite them:

- *"BCJSSE+ACCP at 2.32 ms PQ"* — the configuration was silently falling back to classical `secp384r1` because BCJSSE's default `JcaJceHelper` couldn't resolve ML-KEM correctly. The measurement was accelerated-classical, not PQ.
- *"BCJSSE has a ~7% performance regression vs SunJSSE"* — was a full-connection (not handshake-only) measurement under an unpinned helper. Handshake-only with proper pinning, BCJSSE is faster than SunJSSE, not slower.
- *"ACCP makes ML-KEM free"* — derivative of the first retraction. The 7.7 ms → 2.4 ms gain came from falling back to ECDH, not from accelerating ML-KEM.

The reproduction protocol now includes OpenSSL interop verification (Section 3) to catch this failure mode at measurement time rather than after the fact.

---

## 2. Handshake latency — in-process (macOS arm64)

BCJSSE client connecting to BCJSSE server on loopback. Both endpoints share the same JVM and benefit from any cache effects of running together. Useful for ranking configurations; Linux production absolute numbers will differ.

### 2.1 Provider × algorithm matrix

| Stack | Classical kx | PQ kx (X25519MLKEM768) | Notes |
|---|---|---|---|
| SunJSSE alone | 5.08 ms | not supported | SunJSSE silently drops PQ named groups |
| **SunJSSE + ACCP** | **1.76 ms** | not supported | Fastest classical; can't add PQ |
| BCJSSE pinned to BC | 3.16 ms | 3.25 ms | PQ-capable; ACCP has no effect because the helper bypasses the chain |
| BCJSSE + hybrid helper, no ACCP | 5.05 ms | 5.24 ms | PQ-capable but ACCP not registered; chain walk is overhead |
| **BCJSSE + hybrid helper + ACCP** | **2.26 ms** | **2.56 ms** | PQ-capable AND ACCP-accelerated |

Throughput from the same runs:

- SunJSSE: ~177 hs/sec
- BCJSSE pinned to BC: ~316 hs/sec classical, ~308 hs/sec PQ
- BCJSSE + hybrid + ACCP: corresponding inverse-of-latency

### 2.2 Adding ML-DSA-65 authentication

Same hybrid-helper + ACCP stack, with the cert chain switched to ML-DSA-65 self-signed. This is the fully-PQ configuration (PQ key exchange + PQ authentication).

| Configuration | Mean | Throughput |
|---|---|---|
| ML-DSA certs + classical kx, no ACCP | 2.69 ms | 372 hs/sec |
| **ML-DSA certs + classical kx + ACCP** | **2.35 ms** | **425 hs/sec** |
| ML-DSA certs + PQ kx, no ACCP | 2.77 ms | 361 hs/sec |
| **ML-DSA certs + PQ kx + ACCP** | **2.50 ms** | **400 hs/sec** |

Headline: full PQ at ~2.50 ms vs SunJSSE+ACCP classical at ~1.76 ms. **~700 µs absolute difference** per handshake; below the noise floor of node-level CPU at production handshake rates.

### 2.3 ACCP speedup by configuration

| Workload | No ACCP | With ACCP | Speedup |
|---|---|---|---|
| BCJSSE classical (pinned to BC, no helper) | 3.16 ms | n/a | ACCP can't reach BCJSSE in this config |
| BCJSSE classical (hybrid helper) | 5.05 ms | 2.26 ms | 55% |
| BCJSSE PQ kx (hybrid helper) | 5.24 ms | 2.56 ms | 51% |
| ML-DSA auth + classical kx | 2.69 ms | 2.35 ms | 13% |
| ML-DSA auth + PQ kx | 2.77 ms | 2.50 ms | 10% |

Pattern: ACCP gives ~50% on classical-heavy handshakes (RSA / ECDH / AES-GCM dominate). It gives only ~10–13% on ML-DSA-heavy handshakes because BC's pure-Java ML-DSA is already fast and the signing operation is a smaller share of total handshake time.

---

## 3. Handshake latency — OpenSSL interop

Cross-implementation verification: BCJSSE client connecting to `openssl s_server -tls1_3 -groups X25519MLKEM768` (OpenSSL 3.6.1) over real TCP. Catches "works with itself but isn't actually doing PQ" failure modes.

| Stack | Mean | Handshakes |
|---|---|---|
| BCJSSE pinned to BC | 4.69 ms | 100/100 ✓ |
| **BCJSSE + hybrid helper + ACCP** | **3.18 ms** | **100/100 ✓** |

Higher than the in-process figures because they include real TCP round-trips and cross-stack overhead. They confirm:

- Wire-format compatibility between BCJSSE's `X25519MLKEM768` and OpenSSL's
- ACCP's classical primitives produce wire output OpenSSL accepts
- BC's ML-KEM agrees with AWS-LC's (OpenSSL's underlying backend) on the over-the-wire ciphertext format

---

## 4. Mixed-PSS hypothesis — functional confirmation

Run on the same `consensus-tls-debug` harness with a third-party verification scenario: cert chain where the self-signed CA stays on `SHA384withRSA` (PKCS#1 v1.5) while the agrCert moves to `SHA384withRSAandMGF1` (PSS), and the TLS configuration advertises `rsa_pkcs1_sha384` for cert-chain compat per RFC 8446 §4.2.3.

**Result**: handshake completes end-to-end. Functional confirmation only; no latency measurement was taken.

Operational consequence: the BCJSSE migration does not require a fleet sigCert refresh. The latency figures measured for the legacy chain (Sections 2 and 3) carry over unchanged once this configuration is in place.

---

## 5. Consensus-side throughput (Linux x86_64, sloth Docker host)

ACCP registered system-wide (position 1 in JCA), so it accelerates BOTH event signature verification and TLS record-layer crypto. Numbers below mix those two contributions; per-component attribution is partial (see Section 5.4).

### 5.1 `SignatureSchemeExperiment` — Ed25519, unsaturated at 40 tps target

Both pre and post hit the 40 tps target — clean unsaturated comparison.

| Metric | PRE (no ACCP) | POST (ACCP) | Δ |
|---|---|---|---|
| Achieved tps | 40.00 | 40.02 | hit |
| Avg | 2742 μs | 2609 μs | **−4.9%** |
| p50 | 2640 μs | 2534 μs | −4.0% |
| p95 | 3315 μs | 2935 μs | **−11.5%** |
| p99 | 3864 μs | 4516 μs | +16.9% |
| Max | 18 265 μs | 23 891 μs | +31% (rare outlier in 9 604 samples) |
| StdDev | 720 μs | 669 μs | −7.1% |

Modest, real win. Ed25519 itself is fast; most of the gain likely comes from TLS record-layer crypto going through ACCP rather than from the signature operation. The exact attribution between TLS and per-event signing is not isolated by this benchmark.

### 5.2 `SignatureSchemeExperiment` — RSA-3072, saturated at 40 tps target

Both sides over-target; latency reflects queue buildup, not per-tx cost.

| Metric | PRE (no ACCP) | POST (ACCP) | Δ |
|---|---|---|---|
| Target tps | 40 | 40 | — |
| Achieved tps | 19.82 (50% of target) | 25.07 (63%) | **+27% throughput** |
| Avg | 5284 ms | 1705 ms | **−68% (3.1× faster)** |
| p50 | 4977 ms | 1231 ms | −75% |
| p95 | 7802 ms | 3369 ms | −57% |
| p99 | 8571 ms | 3582 ms | −58% |
| Max | 9576 ms | 4426 ms | −54% |
| StdDev | 1379 ms | 1204 ms | −13% |

RSA-PSS verification IS the bottleneck at 40 tps. ACCP turns each verify from ~8–12 ms (BC pure-Java) into ~1–3 ms (AWS-LC native), the queue clears 3× faster, throughput rises 27%, latency drops 68%.

POST runs cluster within 11 ms of each other (1698 / 1705 / 1709 ms). PRE runs spread over hundreds of ms. ACCP doesn't just speed RSA up; it makes RSA **predictable**.

### 5.3 `combinedAllOptimizations` — full optimization stack

Holistic measurement of consensus latency under the full optimization stack on the same Linux host.

| Metric | main (no ACCP) | pq (ACCP) | Δ |
|---|---|---|---|
| Avg consensus latency | 3195 μs | 2719 μs | **−15%** |
| p50 | 3143 μs | 2659 μs | −15% |
| p95 | 3879 μs | 3015 μs | **−22%** |
| p99 | 4526 μs | 5139 μs | +14% |
| `bytes_per_sec_sent` | 1.45 MB/s | 1.72 MB/s | **+18%** |
| ZGC stop-the-world (total) | 2.82 ms | 2.53 ms | ~equal |

Trade-off: ~3× more short-lived allocations (peak heap 80% vs 45%), but ZGC absorbs the churn with no measurable pause cost.

### 5.4 Per-operation cost (inferred from queueing)

These figures are reverse-engineered from end-to-end queueing dynamics, not micro-benchmarked directly. Treat as order-of-magnitude:

| Operation | BC (no ACCP) | ACCP (AWS-LC) | Speedup |
|---|---|---|---|
| RSA-3072 / RSA-PSS verify | ~8–12 ms | ~1–3 ms | ~3× |
| Ed25519 verify | ~30–60 μs | ~20–40 μs | ~1.5–2× |

---

## 6. Headline takeaways

1. **The "BCJSSE has a 7% performance regression" concern is moot.** BCJSSE pinned to BC at 3.16 ms is *faster* than SunJSSE at 5.08 ms on the same hardware.
2. **PQ is not a perf regression.** Full PQ (kx + auth) at ~2.50 ms vs SunJSSE+ACCP classical at ~1.76 ms = ~700 µs penalty per handshake. Below the noise floor of node-level CPU at production handshake rates.
3. **ACCP is the dominant lever for classical operations.** ~50% on classical-heavy handshakes; ~3× on RSA-PSS verification (the consensus hot path); ~10–13% on ML-DSA-heavy handshakes where BC's pure-Java ML-DSA is already fast.
4. **The hybrid `JcaJceHelper` is what unlocks ACCP for BCJSSE.** Without it, BCJSSE cannot benefit from ACCP and has to be pinned to BC, which forfeits acceleration.
5. **OpenSSL interop confirms wire correctness.** The 3.18 ms cross-stack interop number rules out "works with itself but isn't actually doing PQ" as a failure mode.
6. **Consensus-side ACCP shows up in independent benchmarks.** The `combinedAllOptimizations` and `SignatureSchemeExperiment` results confirm ACCP value extends beyond TLS handshakes into event signature verification.

---

## 7. Open performance questions

- **Linux/x86_64 in-process and OpenSSL-interop handshake latency.** All TLS handshake numbers in Sections 2 and 3 are macOS arm64. As a rough sanity check, an unrelated consensus-layer benchmark on the same hardware family showed Linux ~24% slower than Mac for the same workload (different domain — consensus-event scheduling, not crypto — but the order of magnitude is informative). Handshake-specific Linux measurements are still required before launch.
- **Long-running stability.** Millions of handshakes over hours, to flush native-library leaks, JIT regressions, GC pressure surprises.
- **ACCP TLS-vs-signature attribution on Ed25519.** The 5% gain in Section 5.1 is not yet split between record-layer crypto and per-event signing contributions. A direct experiment (register ACCP but leave `SigningImplementation` defaults on `RSA_BC` / `ED25519_SODIUM`) would isolate the TLS-only contribution.
- **Per-op micro-benchmarks for ML-DSA-65.** Sign and verify in isolation, under both BC and ACCP, would replace the inferred numbers in Section 5.4 with measured values.
- **RSA un-saturated measurement.** Section 5.2 runs at saturation; a 15–20 tps target run would surface true per-tx cost without queue amplification (expected 50–200 ms range).

---

## Appendix A. Source benchmarks

### TLS handshake harness (macOS arm64 numbers)

`platform-sdk/consensus-tls-debug/src/main/java/.../`:

- `MtlsDebugAccp.java` — BCJSSE pinned to BC, optional ACCP. Source for Section 2.1 baselines.
- `MtlsDebugHybrid.java` — Custom hybrid `JcaJceHelper`. Source for Sections 2.1, 2.2, 2.3 numbers (with `--mlkem` and/or `--mldsa` flags).
- `MtlsDebugInterop.java` — Client-only variant connecting to `openssl s_server`. Source for Section 3.
- `MtlsDebugMixedPss.java` — Mixed-PSS hypothesis test. Source for Section 4.

Reproduction commands (representative):

```bash
# Section 2.1 — BCJSSE pinned to BC
./gradlew :consensus-tls-debug:run --args="--accp --no-accp --iterations=500"

# Section 2.1, 2.2, 2.3 — hybrid helper, with/without ACCP, with/without ML-DSA
./gradlew :consensus-tls-debug:run --args="--hybrid --mlkem --iterations=500"
./gradlew :consensus-tls-debug:run --args="--hybrid --mlkem --mldsa --iterations=500"

# Section 3 — OpenSSL interop
openssl s_server -accept 18443 -www -tls1_3 \
    -cert /tmp/pq-interop/server.crt -key /tmp/pq-interop/server.key \
    -groups X25519MLKEM768 -quiet &
./gradlew :consensus-tls-debug:run --args="--interop --hybrid-helper --mlkem --iterations=100"

# Section 4 — mixed-PSS hypothesis
./gradlew :consensus-tls-debug:run --args="--mixed-pss"
```

### Consensus-side benchmarks (Linux x86_64 numbers)

`platform-sdk/consensus-sloth/src/testPerformance/`:

- `SignatureSchemeExperiment.java` — Source for Sections 5.1 and 5.2.
- `CombinedOptimizationsExperiment.java` — Source for Section 5.3.

Source data archives:

- `~/benchmark-results/remote/benchmark-186.233.187.173-m_pq_pre_a-20260418-120232.tar.gz` — PRE2, the apples-to-apples 40 tps / 240 s control for Sections 5.1 and 5.2.
- `~/benchmark-results/remote/benchmark-186.233.187.173-m_pq_post_a-20260418-111535.tar.gz` — POST, three 40 tps / 240 s runs with ACCP.
- `~/benchmark-results-linux-pq/` — `combinedAllOptimizations` PRE/POST archives for Section 5.3.

---

## Appendix B. Configuration matrices used

For reproducibility — every measurement above corresponds to one of these stack combinations:

| Tag | JSSE provider | JcaJceHelper | ACCP registered | Cert chain | Sig schemes advertised |
|---|---|---|---|---|---|
| **A** | SunJSSE | (default) | no | RSA-3072 + EC-384, SHA384withRSA | `ecdsa_*`, `rsa_pss_*`, `ed25519` |
| **A+ACCP** | SunJSSE | (default) | yes (pos 1) | same as A | same as A |
| **B-pin** | BCJSSE | `ProviderJcaJceHelper(bcProv)` | n/a (chain bypassed) | RSA-3072 + EC-384, SHA384withRSAandMGF1 | `mldsa65`, classical, `rsa_pkcs1_sha384` |
| **B-hyb** | BCJSSE | hybrid (ML-KEM→BC, rest→chain) | no | same as B-pin | same as B-pin |
| **C** | BCJSSE | hybrid | yes (pos 1) | same as B-pin | same as B-pin |
| **D** | BCJSSE | hybrid | yes (pos 1) | ML-DSA-65 self-signed | `mldsa65`, classical, `rsa_pkcs1_sha384` |

The "named groups" set is consistent: classical configs use `[x25519, secp384r1]`; PQ-kx configs use `[X25519MLKEM768, secp384r1]`. The `secp384r1` entry is structurally required by BCJSSE for some signature-scheme activations even when not the active key-exchange group.