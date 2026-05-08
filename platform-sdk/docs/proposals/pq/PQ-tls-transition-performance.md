# PQ TLS performance run

## 1. Benchmarks

### 1.1 TLS handshake benchmarks

- Hardware: macOS, JDK 25, BouncyCastle 1.83, ACCP 2.6.0 (locally built with ML-KEM enabled)
- 500 handshakes per trial, 50 warmup iterations before measurement, 3 trials per configuration
- Trial-to-trial variance ~5–10%
- TLS 1.3 throughout, cipher suite `TLS_AES_256_GCM_SHA384`
- "Classical" = `x25519` named group, EC-384 / RSA-3072 chain, classical signatures
- "PQ kx" = `X25519MLKEM768` named group (hybrid x25519 + ML-KEM-768)
- "PQ auth" = `mldsa65` signature scheme, ML-DSA-65 self-signed cert chain

### 1.2 Consensus-side (sloth) benchmarks

With sloth benchmarks (`SignatureSchemeExperiment`, `combinedAllOptimizations`)  the measurements are PQ key exchange + classical auth (RSA-3072 / EC-384)
Consensus-side benchmarks primarily measure the broader effect of introducing ACCP into the runtime, not the isolated impact of PQ TLS.
Hardware: remote Linux box: 32 CPUs, 128 GB RAM, Java 25.0.2 inside a sloth Docker container.
Three runs per configuration, 240 s each, 40 tps target unless noted.

### 1.3 Measurements explicitly retracted

- *"BCJSSE has a ~7% performance regression vs SunJSSE"* — was a full-connection (not handshake-only) measurement under an unpinned helper. Handshake-only with proper pinning, BCJSSE is faster than SunJSSE, not slower.

---

## 2. Loopback handshake benchmarks (macOS arm64)

> **Note**: The handshake benchmarks isolate TLS establishment cost and should not be interpreted as end-to-end node throughput measurements.

BCJSSE client connecting to BCJSSE server on loopback. Both endpoints share the same JVM.
The hybrid `JcaJceHelper` is what unlocks ACCP for BCJSSE.** Without it, BCJSSE cannot benefit from ACCP and has to be pinned to BC, which forfeits acceleration.


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

### 2.2 Adding PQ auth (ML-DSA-65)

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

Pattern: ACCP gives ~50% on classical-heavy handshakes (RSA / ECDH / AES-GCM dominate). It gives only ~10–13% on ML-DSA-heavy handshakes.

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
- BC's ML-KEM agrees with OpenSSL's on the over-the-wire ciphertext format

---

## 4. Consensus-side throughput (Linux x86_64, sloth Docker host)

ACCP registered system-wide (position 1 in JCA), so it accelerates BOTH event signature verification and TLS record-layer crypto.

> **Note**: numbers in this section reflect the values on a slightly modified production code path,
> which is PQ key exchange + classical tls auth (RSA-3072 / EC-384).                                                                                                       
> PQ auth is not yet wired into consensus-side benchmarks; the                                                                                                     
> only full-PQ data points are the handshake-only macOS measurements in §2.2.
 
### 4.1 `SignatureSchemeExperiment` — Ed25519, unsaturated at 40 tps target

Both runs hit the 40 tps target.

| Metric | libsodium | ACCP | Δ |
|---|-----------|---|---|
| Achieved tps | 40.00     | 40.02 | hit |
| Avg | 2742 μs   | 2609 μs | **−4.9%** |
| Max | 18 265 μs | 23 891 μs | +31% (rare outlier in 9 604 samples) |
| StdDev | 720 μs    | 669 μs | −7.1% |

Ed25519 verification is already fast, so ACCP provides smaller relative gains;
The practical side is that it allow us to avoid the dependency on libsodium for ED25519 implementation.

### 4.2 `SignatureSchemeExperiment` — RSA-3072, saturated at 40 tps target

Both sides under 40 tps target.

| Metric | no ACCP | ACCP | Δ |
|---|---|---|---|
| Target tps | 40 | 40 | — |
| Achieved tps | 19.82 (50% of target) | 25.07 (63%) | **+27% throughput** |
| Avg | 5284 ms | 1705 ms | **−68% (3.1× faster)** |
| Max | 9576 ms | 4426 ms | −54% |
| StdDev | 1379 ms | 1204 ms | −13% |

RSA-PSS verification IS the bottleneck at 40 tps. ACCP turns each verify from ~8–12 ms (BC pure-Java) into ~1–3 ms (AWS-LC native), the queue clears 3× faster, throughput rises 27%, latency drops 68%.

ACCP runs cluster within 11 ms of each other (1698 / 1705 / 1709 ms). no ACCP runs spread over hundreds of ms. ACCP doesn't just speed RSA up; it makes RSA **predictable**.

---

## 5. Takeaways
1. **Consensus-side ACCP shows up in independent benchmarks.** The `combinedAllOptimizations` and `SignatureSchemeExperiment` results confirm ACCP value extends beyond TLS handshakes into event signature verification.
2. **ACCP is the dominant gain for classical operations.** ~50% on classical-heavy handshakes; ~3× on RSA-PSS verification (the consensus hot path); ~10–13% on ML-DSA-heavy handshakes where BC's pure-Java ML-DSA is already fast.
3. **PQ possibly not a perf regression.** Full PQ (kx + auth) at ~2.50 ms vs SunJSSE+ACCP classical at ~1.76 ms = ~700 µs penalty per handshake. Appears operationally insignificant at expected handshake rates. Still it needs to be confirmed with sloth benchmarks.
4. **ACCP gain for PQ auth is modest** Still needs to be confirmed with sloth benchmarks as next step work.
