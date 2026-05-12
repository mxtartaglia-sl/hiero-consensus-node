# Experiments — `consensus-tls-debug` harness catalog

This document catalogs every debug variant in the `consensus-tls-debug` module: what it runs, what it validates, and how to invoke it. Use this when you want to reproduce a specific finding or extend the investigation.

All variants share a common pattern: generate certs in-memory, build server + client `SSLContext`s, run an mTLS TLS 1.3 handshake on loopback, report the result. Some variants run a single handshake (correctness tests), others run iteration loops (benchmarks).

## Currently invokable variants

These are wired into `MtlsDebug.main`'s dispatch and can be invoked via:

```bash
./gradlew :consensus-tls-debug:run --args="<flag> [extra args]"
```

| Flag | Class | Purpose |
|---|---|---|
| (none) | `MtlsDebug` | BCJSSE, EC CA + EC agrCert, classical kx. Smoke test of the BCJSSE basics. Supports `--rogue-ca` and `--corrupt` for negative tests. |
| `--java` | `MtlsDebugJava` | SunJSSE with the production gossip key shape (RSA-3072 CA + EC-384 agrCert + `SHA384withRSA`). Demonstrates the classical baseline works on SunJSSE. Supports `--corrupt` to flip a byte in agrCert's signature — handshake fails as expected, proving the framework verifies the signature. |
| `--accp` | `MtlsDebugAccp` | BCJSSE pinned to BC, optional ACCP at JCA position 1. Iterations / warmup supported. The original benchmark harness — but ACCP cannot reach BCJSSE in this configuration. |
| `--hybrid` | `MtlsDebugHybrid` | BCJSSE + custom hybrid `JcaJceHelper` + ACCP. The unified harness used for the canonical performance matrix. Supports `--mlkem` (hybrid PQ kx), `--pure` (pure ML-KEM-768 kx), `--mldsa` (ML-DSA-65 cert chain), `--no-accp`, `--iterations=N`, `--warmup=N`. |
| `--interop` | `MtlsDebugInterop` | Client-only: connects to an external `openssl s_server`. Used to verify wire-format compatibility against a non-BCJSSE peer. Supports `--hybrid-helper` and `--mlkem`. |
| `--mlkem` | `MtlsDebugMlKem` | Single-handshake variant. Default uses `X25519MLKEM768` (hybrid PQ kx). `--pure` switches to `MLKEM768` (no x25519 component). |
| `--mixed-pss` | `MtlsDebugMixedPss` | Verifies that BCJSSE accepts a cert chain where the self-signed CA stays on `SHA384withRSA` (PKCS#1 v1.5) and only the agrCert moves to `SHA384withRSAandMGF1` (RSA-PSS), provided `rsa_pkcs1_sha384` is in the connection's `signatureSchemes` for cert-chain compat per RFC 8446 §4.2.3. |
| `--dual-trust` | `MtlsDebugDualTrust` | Generates a classical RSA self-signed CA AND an ML-DSA-65 self-signed cert. Loads both as trust anchors in the same JSSE trust store. Runs a classical-auth handshake to verify the dual-anchor trust store doesn't disturb the existing path. Validates the Phase 3 trust-store-extension assumption from the proposal. |

## Variants present in source but not currently dispatched

These class files exist in the package but their flags are commented out in `MtlsDebug.main`. They were used during earlier investigation phases. To invoke them, uncomment the corresponding dispatch line in `MtlsDebug.java`:

| Class | Original purpose |
|---|---|
| `MtlsDebugMlKemJava` | SunJSSE attempt at `X25519MLKEM768`. Demonstrates SunJSSE silently drops PQ named groups — handshake falls back to classical. |
| `MtlsDebugPq` | BCJSSE pinned to BC, full PQ chain (ML-KEM kx + ML-DSA-65 auth). Pre-hybrid-helper version. |
| `MtlsDebugPqJava` | SunJSSE attempt at `mldsa65`. Demonstrates SunJSSE silently drops PQ signature schemes. |
| `MtlsDebugPqEcCa` | ML-DSA-65 entity cert signed by an EC CA (mixed-algo chain experiment). |
| `MtlsDebugRsaPss` | BCJSSE with RSA-PSS-only keys (no EC), proving PSS works as the cert signing algorithm. |
| `MtlsDebugGossipPss` | Production gossip key shape (RSA-3072 CA + EC-384 agrCert) with `SHA384withRSAandMGF1` instead of PKCS#1 v1.5. Original RSA-PSS migration validation. |
| `MtlsDebugEcdhTest` | Isolation test for the `ECDH` entry in `jdk.tls.disabledAlgorithms` — proved the disable does NOT block ECDSA signature schemes (the original "ECDH workaround" was unnecessary). |
| `MtlsDebugPsk` | BC raw TLS (`TlsClientProtocol` / `TlsServerProtocol`) with PSK external keys. Demonstrates that PSK-mode TLS 1.3 works in BC's raw API but is not exposed through BCJSSE. |

## Reproducing canonical measurements

To re-run the performance matrix that produced `performance.md`:

```bash
bash _run_matrix.sh
```

The script lives in this directory. It runs all 12 configurations × 3 trials, captures output to `_results.txt`, and the markdown tables in `performance.md` are derived from that file. Total runtime ~7–10 minutes including gradle overhead.

To extend the matrix (e.g., a new auth scheme), edit `_run_matrix.sh` and add a `run "<label>" <flags>` line.

## Reproducing other validations

| Finding | Variant | Command |
|---|---|---|
| Mixed-PSS works (sigCert stays on PKCS#1 v1.5) | `--mixed-pss` | `./gradlew :consensus-tls-debug:run --args="--mixed-pss"` |
| Dual trust anchors coexist | `--dual-trust` | `./gradlew :consensus-tls-debug:run --args="--dual-trust"` |
| Pure ML-KEM-768 kx is supported | `--mlkem --pure` | `./gradlew :consensus-tls-debug:run --args="--mlkem --pure"` |
| OpenSSL interop with hybrid PQ kx | `--interop` | (start `openssl s_server -groups X25519MLKEM768` first; see `MtlsDebugInterop` source for full command line) |
| The framework verifies cert signatures | `--java --corrupt` | `./gradlew :consensus-tls-debug:run --args="--java --corrupt"` (handshake fails as expected) |
| Trust store wins over presented chain | `--rogue-ca` | `./gradlew :consensus-tls-debug:run --args="--rogue-ca"` (handshake fails — trust comes from trust store, not the chain) |

## Source layout

```
platform-sdk/consensus-tls-debug/
├── src/main/java/org/hiero/consensus/tls/debug/
│   ├── MtlsDebug.java            ← entry point, flag dispatch
│   ├── MtlsDebugHybrid.java      ← canonical perf harness
│   ├── MtlsDebugMixedPss.java
│   ├── MtlsDebugDualTrust.java
│   └── ...                       ← other variants
├── libs/
│   └── accp-mlkem.jar            ← locally-built ACCP 2.6.0 with -DTARGET_JDK_VERSION=17
└── build.gradle.kts
```

The locally-built ACCP jar is required because the upstream Maven artifact omits ML-KEM (built for JDK 8+ baseline). Build instructions are in `_archive/ACCP_STRATEGIES.md` if needed for a fresh build.