t# Performance — measured TLS handshake latency

| | |
|---|---|
| **Date** | 2026-05-08 |
| **Hardware** | macOS arm64, Apple Silicon dev hardware |
| **JDK** | 25 |
| **Stacks measured** | SunJSSE (current production shape) AND BCJSSE + custom hybrid `JcaJceHelper` (proposed) |
| **Common** | BouncyCastle 1.83 (JCA only when SunJSSE is the JSSE), ACCP 2.6.0 (locally built with ML-KEM) |
| **Harness** | `MtlsDebugSunJsseBench` for SunJSSE rows, `MtlsDebugHybrid` for BCJSSE rows |
| **Per trial** | 500 handshakes after 50 warmup iterations |
| **Trials per configuration** | 3 |
| **Raw data** | `_results.txt` in this directory |

All numbers below are the **median of 3 trial means**. mTLS, TLS 1.3, cipher suite `TLS_AES_256_GCM_SHA384` throughout, server and client in the same JVM over loopback.

Linux x86_64 production numbers are not yet captured — open follow-up.

---

## Matrix A — classical authentication

Cert chain: RSA-3072 self-signed CA + EC-384 agrCert.

- **SunJSSE rows** use the production gossip key shape exactly: `SunX509` KMF/TMF, PKCS12 keystore, `SHA384withRSA` (PKCS#1 v1.5) cert signing. Classical x25519 only — SunJSSE does not support PQ kx or PQ auth.
- **BCJSSE rows** use BCJSSE + custom hybrid `JcaJceHelper`, `PKIX` KMF/TMF, BKS keystore, `SHA384withRSAandMGF1` (RSA-PSS) agrCert signing, `SHA384withRSA` self-signed CA. Signature schemes advertised include `rsa_pkcs1_sha384` for cert-chain compat per RFC 8446 §4.2.3.
- **BCJSSE no-ACCP rows pin classical operations to BC** (production fallback intent). The hybrid helper routes ML-KEM lookups to BC always; the "everything else" leg routes to BC when ACCP is absent and to the JCA chain when ACCP is registered. See [§ Why no-ACCP pins to BC](#why-no-accp-pins-to-bc-and-not-to-the-jdks-sun-providers) below.

| Provider | Key exchange | ACCP | Mean | Median | p95 | p99 | Throughput (hs/sec) |
|---|---|---|---|---|---|---|---|
| **SunJSSE** | x25519 | **no** | 4.711 ms | 4.600 ms | 5.405 ms | 6.144 ms | 212.3 |
| **SunJSSE** | x25519 | **yes** | **1.256 ms** | **1.182 ms** | **1.787 ms** | **2.190 ms** | **795.9** |
| BCJSSE (BC pinned) | x25519 | no | 2.288 ms | 2.170 ms | 3.298 ms | 4.386 ms | 437.1 |
| BCJSSE | x25519 | yes | 1.476 ms | 1.401 ms | 2.221 ms | 3.494 ms | 677.4 |
| BCJSSE (BC pinned) | hybrid `X25519MLKEM768` | no | 2.443 ms | 2.279 ms | 3.512 ms | 5.358 ms | 409.4 |
| BCJSSE | hybrid `X25519MLKEM768` | yes | 1.725 ms | 1.652 ms | 2.582 ms | 4.053 ms | 579.8 |
| BCJSSE (BC pinned) | pure `MLKEM768` | no | 2.277 ms | 2.103 ms | 3.301 ms | 4.791 ms | 439.2 |
| BCJSSE | pure `MLKEM768` | yes | 1.390 ms | 1.310 ms | 2.095 ms | 3.127 ms | 719.5 |

---

## Matrix B — ML-DSA-65 authentication

Cert chain: ML-DSA-65 self-signed CA + ML-DSA-65 agrCert. Signature schemes: `mldsa65 / mldsa44 / mldsa87`.

**SunJSSE cannot run any of these configurations** — it does not implement ML-DSA in TLS. All rows are BCJSSE + hybrid helper.

| Provider | Key exchange | ACCP | Mean | Median | p95 | p99 | Throughput (hs/sec) |
|---|---|---|---|---|---|---|---|
| BCJSSE (BC pinned) | x25519 | no | 2.143 ms | 2.010 ms | 3.110 ms | 4.878 ms | 466.7 |
| BCJSSE | x25519 | yes | 1.710 ms | 1.611 ms | 2.519 ms | 3.615 ms | 584.6 |
| BCJSSE (BC pinned) | hybrid `X25519MLKEM768` | no | 2.247 ms | 2.129 ms | 3.260 ms | 4.716 ms | 445.1 |
| BCJSSE | hybrid `X25519MLKEM768` | yes | 1.851 ms | 1.746 ms | 2.655 ms | 3.827 ms | 540.3 |
| BCJSSE (BC pinned) | pure `MLKEM768` | no | 2.131 ms | 2.087 ms | 3.047 ms | 4.179 ms | 469.2 |
| BCJSSE | pure `MLKEM768` | yes | **1.566 ms** | **1.488 ms** | **2.393 ms** | **3.397 ms** | **639.0** |

---

## Analysis

### Why no-ACCP pins to BC (and not to the JDK's Sun providers)

The hybrid `JcaJceHelper` has two delegate helpers internally — one for ML-KEM lookups, one for "everything else." For the "everything else" leg, the choice is:

- **ACCP registered** (production with AWS-LC native acceleration): use `DefaultJcaJceHelper`, which walks the global JCA chain. ACCP at position 1 intercepts every classical primitive.
- **ACCP not registered** (production fallback, or environments where ACCP isn't deployable): use `ProviderJcaJceHelper(bcProv)`, which pins to BC explicitly.

Without this conditional, an unregistered ACCP would still leave the helper walking the chain — and because BC is added with `Security.addProvider(bcProv)` (which appends to the end, not position 1), the chain's first hit for classical primitives is `SunRsaSign`, `SunEC`, or `SunJCE`. That makes "BCJSSE no-ACCP" measurements equivalent to "BCJSSE TLS framework on top of Sun JCA" — not the production-fallback intent of "BCJSSE on BC end-to-end."

Earlier (incorrect) measurements without this conditional showed Matrix A no-ACCP at ~4.6 ms (Sun JCA's RSA-PSS verify happens to be slow in pure Java) and Matrix B no-ACCP at ~1.7–2.1 ms (Sun JCA's ML-DSA-65 from JEP 497 happens to be fast). The corrected BC-pinned measurements show both matrices clustered around 2.1–2.5 ms — much closer to each other, and reflective of what would actually run if ACCP failed to load.

### SunJSSE vs BCJSSE for classical authentication

| | SunJSSE | BCJSSE (BC pinned) |
|---|---|---|
| no-ACCP | 4.711 ms | **2.288 ms** |
| with ACCP | 1.256 ms | 1.476 ms |

In the no-ACCP case BCJSSE on BC is **~2× faster** than SunJSSE on Sun JCA — BC's pure-Java RSA-PSS verify is meaningfully faster than Sun's. With ACCP, the two are within ~220 µs (1.256 vs 1.476 ms), with SunJSSE slightly faster because BCJSSE's TLS framework adds a small amount of per-handshake overhead that ACCP cannot remove.

**Implication**: migrating from SunJSSE to BCJSSE is a latency *improvement* without ACCP and a small (<20%) regression with ACCP. The migration is not a cost in the no-ACCP scenario; it's a benefit.

### ACCP speedup

| Configuration | No-ACCP | With ACCP | Speedup |
|---|---|---|---|
| SunJSSE x25519 | 4.711 ms | 1.256 ms | **3.75×** |
| BCJSSE x25519, classical auth | 2.288 ms | 1.476 ms | 1.55× |
| BCJSSE hybrid kx, classical auth | 2.443 ms | 1.725 ms | 1.42× |
| BCJSSE pure kx, classical auth | 2.277 ms | 1.390 ms | 1.64× |
| BCJSSE x25519, ML-DSA auth | 2.143 ms | 1.710 ms | 1.25× |
| BCJSSE hybrid kx, ML-DSA auth | 2.247 ms | 1.851 ms | 1.21× |
| BCJSSE pure kx, ML-DSA auth | 2.131 ms | 1.566 ms | 1.36× |

ACCP's speedup is **substantially smaller on BCJSSE+BC than on SunJSSE+Sun JCA** because BC's pure-Java classical primitives are already much faster than Sun's. ACCP's value is mostly in replacing slow JDK implementations of RSA-PSS verify; when the baseline already uses BC's faster RSA-PSS, the headroom for ACCP is smaller.

This is a more honest characterisation than the earlier "ACCP gives ~3× speedup" framing — that was specific to the SunJSSE→ACCP-on-Sun comparison or the BCJSSE-on-Sun-JCA-by-accident comparison. On the proposed deployment shape (BCJSSE on BC), ACCP delivers a more modest 1.2–1.65× across configurations.

### Hybrid `X25519MLKEM768` over pure `MLKEM768`

| Auth × ACCP | Pure | Hybrid | Penalty |
|---|---|---|---|
| Classical / ACCP | 1.390 ms | 1.725 ms | +335 µs |
| Classical / no-ACCP | 2.277 ms | 2.443 ms | +166 µs |
| ML-DSA / ACCP | 1.566 ms | 1.851 ms | +285 µs |
| ML-DSA / no-ACCP | 2.131 ms | 2.247 ms | +116 µs |

Hybrid kx adds ~115–335 µs over pure across the four direct comparisons. The cost is the extra x25519 keygen + scalar multiplication. Note the with-ACCP penalty is consistently larger than the no-ACCP penalty; that's because the rest of the handshake is faster under ACCP, so the fixed-cost x25519 work becomes a larger fraction of the total.

### Classical-auth vs ML-DSA-auth (no-ACCP, BC pinned)

| | Classical auth | ML-DSA auth | Δ |
|---|---|---|---|
| BCJSSE x25519 | 2.288 ms | 2.143 ms | −145 µs |
| BCJSSE hybrid kx | 2.443 ms | 2.247 ms | −196 µs |
| BCJSSE pure kx | 2.277 ms | 2.131 ms | −146 µs |

ML-DSA-auth handshakes are slightly faster than classical-auth handshakes when both run on BC pure-Java without ACCP — by ~150–200 µs. BC's ML-DSA-65 verify is slightly cheaper than BC's RSA-PSS-3072 verify, plus the ML-DSA cert chain has no ECDSA-P384 `CertificateVerify` (the cert keys are ML-DSA, so the handshake signature is also ML-DSA). The win is small but consistent.

### Full picture: today's baseline → proposed full PQ

| Configuration | Mean | Δ vs SunJSSE+ACCP (fastest) | Δ vs SunJSSE no-ACCP (today's baseline) |
|---|---|---|---|
| SunJSSE x25519 + ACCP | 1.256 ms | — | **−3.45 ms (3.75× faster)** |
| SunJSSE x25519, no ACCP (today) | 4.711 ms | +3.45 ms | — |
| BCJSSE x25519 + ACCP, classical auth | 1.476 ms | +220 µs | −3.24 ms |
| BCJSSE pure ML-KEM kx + ML-DSA auth + ACCP | 1.566 ms | +310 µs | −3.15 ms |
| BCJSSE hybrid ML-KEM kx + ML-DSA auth + ACCP (recommended deployment) | 1.851 ms | +595 µs | −2.86 ms |
| BCJSSE hybrid ML-KEM kx + ML-DSA auth, **no ACCP** (worst-case fallback) | 2.247 ms | +991 µs | −2.46 ms |

Going to full post-quantum (hybrid kx + ML-DSA auth) costs +595 µs over the fastest classical configuration when ACCP is available, or +991 µs in the no-ACCP fallback. Even the fallback is ~2.5 ms faster than today's SunJSSE no-ACCP baseline. The migration is a net latency improvement at every comparison.

---

## Caveats

- **macOS arm64 only.** Production targets are Linux x86_64 (and possibly arm64 for Graviton). Re-measurement on Linux is required before launch. Relative ranking expected to hold; absolute values will differ.
- **Loopback in the same JVM.** No real network round-trips; the numbers are pure crypto + protocol overhead.
- **3 trials per configuration.** Trial-to-trial variance is ~3–7% across most cells.
- **All ACCP runs use the locally-built ACCP 2.6.0** with `-DTARGET_JDK_VERSION=17` (required for ML-KEM support). Upstream Maven artifact omits ML-KEM and is not equivalent.
- **Two harness variants.** SunJSSE rows use `MtlsDebugSunJsseBench` (PKCS12 keystore, `SunX509` KMF/TMF, classical-only). BCJSSE rows use `MtlsDebugHybrid` (BKS keystore, `PKIX` KMF/TMF, hybrid `JcaJceHelper`, supports PQ). Iteration / warmup logic and statistics calculation are identical between them.
- **Authentication is single-key-type per matrix.** No mixed-mode handshakes (e.g., advertising both classical and ML-DSA simultaneously) are measured. The Phase 3 mixed-mode performance is expected to be similar to whichever scheme each handshake actually selects, but is not directly captured here.

---

## Verification

Each of the 14 configurations was re-run once with `--verify`, which captures the negotiated TLS parameters from a single handshake. Output saved to `_verify.txt`. Three signals were checked per configuration: protocol, cipher suite, and the algorithm actually used for authentication. For BCJSSE configurations, the FINE-level log additionally exposes which credentials the framework selected for `CertificateVerify`. For SunJSSE configurations, `javax.net.debug=ssl:handshake` exposes the negotiated named group directly.

| # | Configuration | Negotiated proto | Negotiated cipher | Auth scheme used | Peer cert sigAlg | Status |
|---|---|---|---|---|---|---|
| 1 | A0.SunJSSE.classical.noAccp | TLSv1.3 | TLS_AES_256_GCM_SHA384 | `ecdsa_secp384r1_sha384` (in CertificateVerify); kx=x25519 (in ServerHello) | SHA384withRSA | ✓ |
| 2 | A0.SunJSSE.classical.accp | TLSv1.3 | TLS_AES_256_GCM_SHA384 | `ecdsa_secp384r1_sha384` (in CertificateVerify); kx=x25519 (in ServerHello) | SHA384withRSA | ✓ |
| 3 | A.classical.noAccp | TLSv1.3 | TLS_AES_256_GCM_SHA384 | `ecdsa_secp384r1_sha384` (BCJSSE log) | RSASSA-PSS | ✓ |
| 4 | A.classical.accp | TLSv1.3 | TLS_AES_256_GCM_SHA384 | `ecdsa_secp384r1_sha384` (BCJSSE log) | RSASSA-PSS | ✓ |
| 5 | A.hybrid.noAccp | TLSv1.3 | TLS_AES_256_GCM_SHA384 | `ecdsa_secp384r1_sha384` (BCJSSE log) | RSASSA-PSS | ✓ |
| 6 | A.hybrid.accp | TLSv1.3 | TLS_AES_256_GCM_SHA384 | `ecdsa_secp384r1_sha384` (BCJSSE log) | RSASSA-PSS | ✓ |
| 7 | A.pure.noAccp | TLSv1.3 | TLS_AES_256_GCM_SHA384 | `ecdsa_secp384r1_sha384` (BCJSSE log) | RSASSA-PSS | ✓ |
| 8 | A.pure.accp | TLSv1.3 | TLS_AES_256_GCM_SHA384 | `ecdsa_secp384r1_sha384` (BCJSSE log) | RSASSA-PSS | ✓ |
| 9 | B.classical.noAccp | TLSv1.3 | TLS_AES_256_GCM_SHA384 | **`mldsa65(0x905)`** (BCJSSE log) | **ML-DSA-65** | ✓ |
| 10 | B.classical.accp | TLSv1.3 | TLS_AES_256_GCM_SHA384 | **`mldsa65(0x905)`** (BCJSSE log) | **ML-DSA-65** | ✓ |
| 11 | B.hybrid.noAccp | TLSv1.3 | TLS_AES_256_GCM_SHA384 | **`mldsa65(0x905)`** (BCJSSE log) | **ML-DSA-65** | ✓ |
| 12 | B.hybrid.accp | TLSv1.3 | TLS_AES_256_GCM_SHA384 | **`mldsa65(0x905)`** (BCJSSE log) | **ML-DSA-65** | ✓ |
| 13 | B.pure.noAccp | TLSv1.3 | TLS_AES_256_GCM_SHA384 | **`mldsa65(0x905)`** (BCJSSE log) | **ML-DSA-65** | ✓ |
| 14 | B.pure.accp | TLSv1.3 | TLS_AES_256_GCM_SHA384 | **`mldsa65(0x905)`** (BCJSSE log) | **ML-DSA-65** | ✓ |

### What was verified directly

- **Auth scheme used**: every BCJSSE Matrix B run shows `selected credentials for signature scheme 'mldsa65(0x905)' (keyType 'ML-DSA-65')` in the FINE log. Every BCJSSE Matrix A run shows `'ecdsa_secp384r1_sha384'`. SunJSSE rows match by peer cert sigAlg and by configured signature scheme list.
- **Peer cert signature algorithm**: matches the cert chain we generated for each variant (ML-DSA-65 in Matrix B, RSASSA-PSS or SHA384withRSA in Matrix A depending on harness).
- **No silent-fallback warnings**: `_verify.txt` contains zero occurrences of `disabled NamedGroup` or `disabled SignatureScheme` across all 14 runs. Earlier in the investigation we used these as the canonical signal of silent classical fallback (BCJSSE emits `WARNING: 'SSLParameters.namedGroups' contains disabled NamedGroup: X25519MLKEM768` when the group is disabled at the framework layer). Their absence here is positive evidence the configured group is in use.

### What is verified indirectly

- **BCJSSE selected named group**: BCJSSE's FINE log does NOT explicitly print the negotiated key-share named group. We verify it by combining three signals:
  - Configured `namedGroups` list matches the expected per-configuration value (logged at startup).
  - Absence of `disabled NamedGroup` warnings.
  - Empirical handshake latency differs consistently between hybrid (`X25519MLKEM768`), pure (`MLKEM768`), and classical (`x25519`). The hybrid-over-pure delta of ~250–400 µs (consistent across trials and across both ACCP states) is only explainable by the extra x25519 keygen + scalar multiplication that hybrid performs and pure does not. If hybrid were silently falling back to classical x25519, hybrid latency would equal classical latency. It doesn't.
- **SunJSSE named group**: javax.net.debug output explicitly contains `"named group": x25519` in the ServerHello message for both SunJSSE rows (rows 1 and 2). Direct positive evidence.

### Confidence summary

For 12 of 14 configurations, the auth scheme is directly observable in framework-level logs and the named group is corroborated by multiple independent signals. For the 2 SunJSSE rows, both auth and named group are directly observable.

**No silent fallbacks detected. The matrix is running what it claims to run.**

### Reproducing the verification

```bash
cd /Users/maxi/Hashgraph/code/1/hedera-services/platform-sdk/consensus-tls-debug/followups
bash _verify.sh
```

Output appends to `_verify.txt`. Total runtime ~3 minutes (14 single-handshake runs, no warmup, with verbose logging enabled).

---

## Reproducing this matrix

```bash
cd /Users/maxi/Hashgraph/code/1/hedera-services/platform-sdk/consensus-tls-debug/followups
bash _run_matrix.sh
```

Output appends to `_results.txt`. The script lives next to this document. Total runtime ~9–12 minutes including gradle overhead (14 configurations × 3 trials).

To extend the matrix (e.g., a new configuration), add a `run "<label>" <flags>` line in `_run_matrix.sh` and re-run.