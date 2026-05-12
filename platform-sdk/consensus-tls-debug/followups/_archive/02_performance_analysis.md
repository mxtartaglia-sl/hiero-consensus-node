# Item 2: Performance Analysis — BC, BCJSSE, AWS-LC / BoringSSL

**Question for the team**: what is the real cost of each TLS stack option on production-target hardware, and which combination gives us the best throughput for our workload?

**Owner**: Maxi
**Est. effort**: 1–2 days
**Status**: not started, depends on item 1

---

## What we already know

### Handshake latency (macOS arm64, JDK 25, 500 iterations × 3 trials)

All numbers are mean handshake latency from `MtlsDebugAccp` / `MtlsDebugHybrid` / `MtlsDebugInterop`:

| Stack | Classical | PQ kx (X25519MLKEM768) | PQ kx + ML-DSA auth |
|---|---|---|---|
| SunJSSE alone | 5.08 ms | — (not supported) | — |
| SunJSSE + ACCP | **1.76 ms** | — (not supported) | — |
| BCJSSE pinned to BC | 3.16 ms | 3.25 ms | 2.69 ms |
| BCJSSE + hybrid helper, no ACCP | 5.05 ms | 5.24 ms | 2.77 ms |
| BCJSSE + hybrid helper + ACCP | **2.26 ms** | **2.56 ms** | **2.50 ms** |

### OpenSSL interop (confirmed PQ)

Connecting BCJSSE client to `openssl s_server -groups X25519MLKEM768`:

| Stack | Mean | Handshakes |
|---|---|---|
| BCJSSE pinned to BC | 4.69 ms | 100/100 ✓ |
| BCJSSE + hybrid + ACCP | 3.18 ms | 100/100 ✓ |

### What was reported earlier but RETRACTED

- "BCJSSE+ACCP classical is 2.4 ms, PQ is also 2.4 ms" — incorrect, the PQ was silently falling back to `secp384r1`. Fixed in the hybrid helper experiment.
- "BCJSSE has a ~7% regression vs SunJSSE" — this was a full-connection measurement (not handshake-only). Handshake-only, BCJSSE is actually faster than SunJSSE.

### Already known characteristics

- ACCP's classical acceleration is real and significant (~50% faster RSA/ECDH/AES vs BC pure Java).
- ACCP does NOT register ML-KEM in its default maven artifact. Local build needed with `-DTARGET_JDK_VERSION=17`.
- Even with local ACCP ML-KEM, its `MLKEMParameterSpec` class is incompatible with BCJSSE's expectations — BCJSSE must use BC for ML-KEM.
- ACCP's ML-DSA IS compatible with BC — cross-provider signing works per ACCP's test suite and our verification.
- BC's pure-Java ML-KEM is fast (~70 µs overhead in handshake vs classical).
- BC's pure-Java ML-DSA is fast enough that ACCP only gives ~13% speedup on ML-DSA-signing handshakes.

---

## Gaps to fill

### Platform coverage

All existing benchmarks are **macOS arm64** (M-series Mac). Production targets are **Linux x86_64** (AWS EC2) and possibly **Linux arm64** (Graviton). Relative rankings should hold, but absolute numbers will differ — we need to rerun the benchmark matrix on real production hardware.

Specifically:
- ACCP's native library performance is architecture-dependent. x86_64 AES-NI vs arm64 NEON.
- BCJSSE is pure Java; less hardware-dependent.
- JVM JIT behavior can differ between macOS and Linux even on the same architecture.

### Non-handshake workload

All current benchmarks measure **handshake latency only**. In production gossip, handshakes are a fraction of total CPU time. We should also measure:

1. **Sustained throughput**: AEAD cipher performance (AES-256-GCM) under continuous encrypted data flow. ACCP's hardware-accelerated AES-NI should dominate here.
2. **Event signature verification**: the real hot path. Hundreds to thousands of `RSA.verify` or `Ed25519.verify` per second on each node. Independent of TLS. Should benchmark both `Signature.verify` throughput and full consensus throughput.
3. **Event signing**: every self-event is signed. Lower frequency than verification but still on the hot path.

### Alternative TLS stacks not yet tested

1. **netty-tcnative-boringssl-static** — Netty's binding to BoringSSL. Has classical TLS 1.3 and (in recent versions) PQ. Not JSSE-compatible — uses `io.netty.handler.ssl.SslContext`.
2. **s2n-tls-java**: doesn't exist (confirmed earlier). Skip.
3. **Panama/FFI to OpenSSL 3.5+**: custom bindings, substantial work. Only worth it if the Netty path doesn't work.
4. **Conscrypt** with a custom BoringSSL build that has PQ: theoretically possible but requires building Conscrypt from source with a modern BoringSSL.

### Sustained / stress testing

All benchmarks are short-lived (seconds). For production confidence:
- **Long-running handshake stress**: millions of handshakes over hours. Checks for memory leaks, native-library stability, JIT steady state, GC pressure.
- **Concurrent connections**: production gossip has 20–100+ simultaneous TLS connections. Benchmark parallel handshake throughput, not sequential.
- **Reconnect storms**: network blips cause many peers to reconnect simultaneously. Measure p99 handshake latency under bursty load.

---

## Benchmark plan

### Environment matrix

| Platform | JDK | Purpose |
|---|---|---|
| macOS arm64 | 25 | Dev/iteration (already have baseline) |
| Linux x86_64 (EC2 c7i.2xlarge or similar) | 25 | Primary production target |
| Linux arm64 (EC2 c7g.2xlarge or Graviton) | 25 | Alternative production target |
| Linux x86_64 | 27 EA | JDK 27 + JEP 527 native PQ |

### Stack matrix (per environment)

1. SunJSSE alone
2. SunJSSE + ACCP
3. BCJSSE pinned to BC
4. BCJSSE + hybrid helper + ACCP
5. BCJSSE + hybrid helper + ACCP + ML-DSA certs (fully PQ)
6. netty-tcnative-boringssl (if PQ works)
7. SunJSSE on JDK 27 EA (native PQ)

### Workload matrix (per stack)

1. **Handshake latency**: 500 iterations, sequential (what we have today)
2. **Handshake throughput**: concurrent handshakes, measure p99 under load
3. **Sustained bulk encryption**: 1 GB of data through an established session, measure MB/s
4. **Event signature verification**: standalone benchmark for RSA-3072 verify and Ed25519 verify
5. **Reconnect storm**: 100 simultaneous handshakes from a cold start

### Measurement approach

For consistency:
- Same cert chain (RSA-3072 CA + EC-384 agreement with PSS, or ML-DSA-65 when PQ auth)
- Same cipher suite (TLS_AES_256_GCM_SHA384)
- Same named groups per stack (x25519 for classical, X25519MLKEM768 for PQ)
- 50 warmup iterations before measurement
- Multiple trials (3–5) to check variance
- Report mean, median, p95, p99, throughput

---

## Deliverable

A benchmark report document with:

1. **Executive summary**: one-paragraph answer to "which stack should we use for production."
2. **Environment description**: hardware, JDK version, library versions.
3. **Full results matrix**: per environment, per stack, per workload.
4. **Key findings**: 3–5 bullet points highlighting surprises or recommendations.
5. **Cost analysis**: handshake CPU per gossip connection, total CPU for event verification at target TPS. What fraction of a production node's CPU does crypto consume?
6. **Recommendation**: one primary stack + one fallback.

Plus raw benchmark data in `results/` subdirectory (CSV or JSON) for reproducibility.

---

## Open questions

1. What's the target gossip handshake rate? TPS? This sets the crypto load floor.
2. What fraction of a production node's CPU does TLS + event signatures consume today? Without this baseline, speedups are unmoored from business value.
3. Is AES-NI (x86_64) or Crypto Extension (arm64) the bottleneck, or is it RSA signing/verification? The answer changes which ACCP acceleration matters most.
4. Should we also benchmark FIPS-certified ACCP (AWS-LC-FIPS)? Relevant if Hedera needs FIPS compliance for some deployments.
5. Is there a representative "gossip trace" we can replay to benchmark real workloads vs synthetic handshake loops?
6. Do we care about cold-start latency? Node startup includes loading BC, BCJSSE, ACCP's native library, generating agreement keys, establishing all peer connections. A 1-second cold start is very different from a 30-second cold start for operational experience.

---

## Reproduction scripts

To be added as benchmarks run. Initial structure:

```
followups/benchmarks/
├── handshake_latency.sh        # wraps MtlsDebugAccp / MtlsDebugHybrid
├── event_signature_verify.sh   # standalone JCA benchmark
├── bulk_encryption.sh          # large-data TLS throughput
├── concurrent_handshakes.sh    # parallel handshake stress
└── results/                    # output CSVs per run
```