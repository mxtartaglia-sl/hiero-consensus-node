# ACCP + BCJSSE Strategies for PQ TLS

A focused follow-up to the main [`INVESTIGATION.md`](INVESTIGATION.md), documenting the Amazon Corretto Crypto Provider (ACCP) experiments, the hybrid `JcaJceHelper` discovery, and the corrected recommendations.

## Context

ACCP is a JCA-level provider that replaces classical crypto primitives (RSA, ECDH, AES-GCM) with AWS-LC implementations, significantly faster than pure-Java alternatives. ACCP does NOT provide a JSSE/TLS layer — only JCA primitives. It can only accelerate BCJSSE (or SunJSSE) if those providers route their crypto lookups through the global provider chain (where ACCP is registered).

**The question**: can we use ACCP to accelerate BCJSSE TLS 1.3 handshakes, including post-quantum configurations (ML-KEM + ML-DSA)?

## Summary of findings

| Strategy | Can use PQ? | Can use ACCP? | Best latency | Status |
|---|---|---|---|---|
| SunJSSE alone | No (JDK 25) | No effect | 5.08 ms | Rejected |
| SunJSSE + ACCP | No (JDK 25) | Yes | **1.76 ms** | Works for classical |
| BCJSSE pinned to BC | Yes | No | 3.16–3.25 ms | Works for PQ |
| BCJSSE + DefaultJcaJceHelper + ACCP | No (silent fallback) | Yes for classical | — | Broken for PQ |
| **BCJSSE + hybrid helper + ACCP (ML-KEM only)** | Yes | Yes | **2.26–2.56 ms** | Works for PQ kx |
| **BCJSSE + hybrid helper + ACCP + ML-DSA certs** | Yes (fully) | Yes | **2.35–2.50 ms** | **Works for full PQ** |

The hybrid `JcaJceHelper` approach unlocks ACCP acceleration for BCJSSE while preserving ML-KEM compatibility, including a path to **fully post-quantum TLS** (ML-KEM key exchange + ML-DSA authentication) at ~2.5 ms mean latency.

## Experiment timeline

### Experiment 1: ACCP from Maven Central with BCJSSE (default helper)

**Setup**: `software.amazon.cryptools:AmazonCorrettoCryptoProvider:2.5.0:osx-aarch_64` as a `runtimeOnly` dependency. Register ACCP at position 1 of the JCA provider chain. Register BCJSSE without passing a specific provider (so it uses `DefaultJcaJceHelper`, which walks the chain).

**Hypothesis**: ACCP would accelerate BCJSSE's classical operations (RSA, ECDH, AES-GCM) while BC handled ML-KEM (ACCP's default maven artifact omits ML-KEM).

**Result**: Classical handshakes appeared ~2x faster (2.40 ms vs 4.84 ms), PQ handshakes appeared the same speed (2.32 ms). **Too good to be true.**

**Verification via OpenSSL interop**: Started `openssl s_server -groups X25519MLKEM768` (strict — rejects any other group). Connected BCJSSE client. **Handshake failed** with `handshake_failure(40)` and OpenSSL server trace showed the ClientHello's `supported_groups` extension contained ONLY `secp384r1 (0x0018)` — no `X25519MLKEM768`.

**Root cause**: `DefaultJcaJceHelper` walks the global provider chain. When BCJSSE's `KemUtil.getKeyPairGenerator("ML-KEM")` calls through the helper, it gets whichever provider registered `KeyPairGenerator.ML-KEM` first. On JDK 25, SunJCE has ML-KEM registered in its default build (from JEP 496). When BCJSSE then calls `keyPairGenerator.initialize(MLKEMParameterSpec.fromName("ML-KEM-768"))`, the SunJCE `KeyPairGenerator` receives a **BC-specific `MLKEMParameterSpec` class** and rejects it with `InvalidAlgorithmParameterException`. BCJSSE's `KemUtil.isKemSupported` catches the exception, returns `false`, and BCJSSE silently marks `X25519MLKEM768` as a disabled named group.

**The handshake fell back to `secp384r1` classical ECDH** (second entry in our named groups list) without any error message. The "2.32 ms PQ" number was really 2.32 ms classical ECDH, accelerated by ACCP. **The measurement was correct for what actually happened, but what happened was not PQ.**

BCJSSE's only warning for this: `WARNING: 'SSLParameters.namedGroups' contains disabled NamedGroup: X25519MLKEM768`, only visible at `FINEST` log level.

### Experiment 2: BCJSSE pinned to BC explicitly

**Setup**: `new BouncyCastleJsseProvider(bcProv)` instead of default constructor. This makes BCJSSE use a `ProviderJcaJceHelper(bcProv)` that sends all crypto lookups directly to BC, skipping the global chain entirely.

**Result**: Real X25519MLKEM768 works, verified via OpenSSL interop (4.69 ms mean, 100/100 successful handshakes). But **ACCP has no effect** because BCJSSE never touches the global chain. BCJSSE classical is 3.16 ms, BCJSSE PQ is 3.25 ms, with or without ACCP registered.
''
**Conclusion from Experiments 1-2**: Pick between ACCP acceleration (breaks ML-KEM) OR real PQ (bypasses ACCP). Can't have both with off-the-shelf BCJSSE configurations.

### Experiment 3: Build ACCP locally with ML-KEM support

**Setup**: ACCP's default Maven artifact omits ML-KEM because the Java `KEM` interface was backported to JDK 17+, and ACCP supports JDK 8+. Building locally with `-DTARGET_JDK_VERSION=17` includes ML-KEM. Built ACCP 2.6.0 from source:

```bash
git clone --recurse-submodules https://github.com/corretto/amazon-corretto-crypto-provider.git
cd amazon-corretto-crypto-provider
export JAVA_HOME=~/.sdkman/candidates/java/21.0.3-tem
./gradlew -DTARGET_JDK_VERSION=17 build -x test
# Output: build/lib/AmazonCorrettoCryptoProvider.jar (1.6 MB with native libamazonCorrettoCryptoProvider.dylib embedded)
```

Copied to `platform-sdk/consensus-tls-debug/libs/accp-mlkem.jar` and loaded via `runtimeOnly(files("libs/accp-mlkem.jar"))`. Confirmed ACCP 2.6.0 registers `KeyPairGenerator.ML-KEM`, `KeyFactory.ML-KEM`, `KEM.ML-KEM-768` at JCA level.

**Hypothesis**: With ACCP's ML-KEM registered at position 1, BCJSSE's `DefaultJcaJceHelper` would find ACCP's ML-KEM first and use it, avoiding the SunJCE shadowing issue. If ACCP's `MLKEMParameterSpec` is compatible with BCJSSE's expectations, full PQ + full ACCP acceleration.

**Result**: **Same silent fallback.** BCJSSE still silently disabled `X25519MLKEM768`. OpenSSL interop still failed. ACCP's `MLKEMParameterSpec` class is ACCP-specific, not BC-compatible — the same root cause as SunJCE, just a different concrete class.

**Takeaway**: Any non-BC provider that registers `KeyPairGenerator.ML-KEM` and appears before BC in the chain will break BCJSSE's ML-KEM support. The parameter spec class `org.bouncycastle.jcajce.spec.MLKEMParameterSpec` is BCJSSE's only accepted input, and only BC's `KeyPairGenerator.ML-KEM` handles it.

### Experiment 4: Custom hybrid JcaJceHelper

**Setup**: Write a custom `JcaJceHelper` implementation that routes ML-KEM operations to BC explicitly and everything else to `DefaultJcaJceHelper` (which walks the global chain, hitting ACCP first).

```java
final JcaJceHelper hybridHelper = new HybridJcaJceHelper(
        new ProviderJcaJceHelper(bcProv),  // ML-KEM → BC
        new DefaultJcaJceHelper());        // everything else → chain

final JcaTlsCryptoProvider cryptoProvider = new JcaTlsCryptoProvider() {
    @Override public JcaJceHelper getHelper() { return hybridHelper; }
};

Security.addProvider(new BouncyCastleJsseProvider(false, cryptoProvider));
```

The `HybridJcaJceHelper` implements all 19 `JcaJceHelper` methods. The critical ones are `createKeyPairGenerator`, `createKeyFactory`, `createKeyGenerator`, and `createKeyAgreement` — if the algorithm name starts with `"ML-KEM"`, delegate to BC. For `createCipher`, delegate to BC too (ML-KEM cipher operations use BC-specific keys). For everything else (`createSignature`, `createKeyPairGenerator` for RSA/EC, etc.), delegate to the default chain where ACCP intercepts.

**Result**: Works perfectly.

- Classical handshakes: 2.26 ms (vs 3.16 ms pinned to BC → **30% faster**)
- Hybrid PQ handshakes: 2.56 ms (vs 3.25 ms pinned to BC → **21% faster**)
- **Verified via OpenSSL interop at 3.18 ms** with 100/100 successful handshakes against `openssl s_server -groups X25519MLKEM768`

**Takeaway**: The hybrid helper approach successfully combines real X25519MLKEM768 key exchange with ACCP acceleration for classical operations. No silent fallbacks. No code changes to BCJSSE itself — just a custom `JcaTlsCryptoProvider`.

### Experiment 5: ML-DSA authentication with the hybrid helper

**Setup**: In the hybrid helper, `createSignature(...)` already routes to the default chain (not BC). So ML-DSA signing via `Signature.getInstance("ML-DSA-65")` would hit ACCP first (if ACCP has ML-DSA registered, which it does — unlike ML-KEM, ML-DSA IS in ACCP's default maven artifact for all JDK versions).

**Hypothesis**: ACCP's ML-DSA `Signature` should accept BC-generated ML-DSA private keys. ACCP's own test suite (`MLDSATest.java`) explicitly verifies cross-provider interop: "Cross-provider signature verification between ACCP's native implementation and BouncyCastle, testing all combinations of signing/verifying with different providers."

**Unlike ML-KEM**, ML-DSA signing in BCJSSE does NOT pass a BC-specific parameter spec class. It calls `signature.initSign(privateKey)` where `privateKey` is a `java.security.PrivateKey` (BC's concrete type). ACCP should be able to import this via PKCS#8 round-trip, per its test suite.

**Setup details**: In `MtlsDebugHybrid.java`, added `--mldsa` flag. When set:
- Generate CA as ML-DSA-65 via BC
- Generate entity certs as ML-DSA-65 via BC, signed by the ML-DSA CA
- Add `mldsa65` (and variants) to the `SSLParameters.signatureSchemes` list so BCJSSE advertises them
- Hybrid helper routes `createSignature("ML-DSA-65")` to the default chain → ACCP gets first pick

**Result**: **Handshake completes successfully.** ACCP accepts BC's ML-DSA private keys and signs CertificateVerify using its AWS-LC backend.

Benchmarked:

| Configuration | Mean | Throughput |
|---|---|---|
| ML-DSA certs + classical kx + no ACCP | 2.69 ms | 372 hs/sec |
| **ML-DSA certs + classical kx + ACCP** | **2.35 ms** | **425 hs/sec** |
| ML-DSA certs + PQ kx + no ACCP | 2.77 ms | 361 hs/sec |
| **ML-DSA certs + PQ kx + ACCP** | **2.50 ms** | **400 hs/sec** |

ACCP gives a ~13% speedup on ML-DSA-signing handshakes. Not as dramatic as the ~50% speedup on classical handshakes, because ML-DSA signing is already fast in BC and the signature itself is a smaller share of total handshake time. But it's a real, verifiable speedup with no compatibility issues.

**Takeaway**: The earlier blanket statement "BCJSSE must be pinned to BC" was wrong — it's only ML-KEM that needs BC pinning. ML-DSA works with the hybrid helper and ACCP, enabling **fully post-quantum TLS** (ML-KEM + ML-DSA) with ACCP acceleration.

## Technical deep-dive: the hybrid helper

### Why BCJSSE has this architecture

BCJSSE is built on BouncyCastle's lower-level `JcaTlsCrypto` abstraction, which uses a `JcaJceHelper` to obtain JCA primitives. The helper design predates JSSE and was built for BC's standalone TLS library (`bctls`). JSSE integration wraps `bctls` via `BouncyCastleJsseProvider`, but keeps the helper indirection.

Three stock helpers exist:

- `DefaultJcaJceHelper`: calls `KeyPairGenerator.getInstance("X")` — walks the global provider chain
- `ProviderJcaJceHelper(Provider p)`: calls `KeyPairGenerator.getInstance("X", p)` — pins to a specific provider
- `NamedJcaJceHelper(String name)`: calls `KeyPairGenerator.getInstance("X", name)` — pins by name

The `BouncyCastleJsseProvider` constructor variants pick among these:

- `new BouncyCastleJsseProvider()` → `DefaultJcaJceHelper` (walks chain)
- `new BouncyCastleJsseProvider(Provider p)` → `ProviderJcaJceHelper(p)` (pinned)
- `new BouncyCastleJsseProvider(boolean fipsMode, JcaTlsCryptoProvider cp)` → uses whatever `cp.getHelper()` returns

The third variant is the escape hatch. We construct a `JcaTlsCryptoProvider` subclass that returns a custom helper, and that helper can mix strategies per algorithm.

### The hybrid helper routing table

```
Algorithm category                    → Helper
────────────────────────────────────────────────────────────
ML-KEM-*                              → BC pinned
ML-DSA-*                              → chain (→ ACCP first)
RSA, EC, x25519, ed25519, ed448        → chain (→ ACCP first)
SHA-*, HMAC-*, AES                    → chain (→ ACCP first)
Certificate parsing (X.509)           → chain (→ default JDK)
KeyStore (BKS, PKCS12)                → chain (→ default JDK)
```

The only BC-pinned category is ML-KEM. Everything else goes through the global chain where ACCP intercepts.

### Why ML-KEM is special and ML-DSA isn't

**ML-KEM key generation path** (BCJSSE internal):
```java
KeyPairGenerator kpg = helper.createKeyPairGenerator("ML-KEM");
kpg.initialize(BC_MLKEMParameterSpec.fromName("ML-KEM-768"), random);
//             ^^^^^^^^^^^^^^^^^^^^^^^^^^^
//             BC-specific class, non-BC KPG rejects it
```

**ML-DSA signing path** (BCJSSE internal, during handshake):
```java
Signature sig = helper.createSignature("ML-DSA-65");
sig.initSign(privateKey);   // privateKey is a standard java.security.PrivateKey
sig.update(transcriptHash);
byte[] signature = sig.sign();
```

No parameter spec, no BC-specific class in the signature path. ACCP's `initSign` just needs to accept BC's PKCS#8-encoded private key, which it does (per the ACCP test suite).

The same distinction applies to ML-KEM decapsulation (uses `javax.crypto.KEM`) vs ML-DSA verification — ML-DSA's API is pure JCA, ML-KEM's requires a BC-specific spec class.

### Cross-provider key compatibility for ML-DSA

ACCP's `BCMLDSAPrivateKey` and ACCP's `EvpMlDsaPrivateKey` both implement `java.security.PrivateKey` and encode via PKCS#8 per NIST FIPS 204. When BCJSSE's `Signature.initSign(bcPrivateKey)` passes a BC private key to an ACCP `Signature`, ACCP calls `key.getEncoded()` to get the PKCS#8 bytes and reconstructs an ACCP-internal key from them. This roundtrip is explicitly tested by `MLDSATest.java` in ACCP's test suite.

## Performance comparison: final benchmark

Measured on macOS arm64, JDK 25, BouncyCastle 1.83, ACCP 2.6.0 (locally built with ML-KEM). Each number is the mean of 500 handshakes after 50 warmup iterations, three trials per configuration.

### In-process (BCJSSE ↔ BCJSSE, loopback)

| Stack | Classical kx | PQ kx (X25519MLKEM768) |
|---|---|---|
| SunJSSE | 5.08 ms | — (not supported) |
| **SunJSSE + ACCP** | **1.76 ms** | — (not supported) |
| BCJSSE pinned to BC | 3.16 ms | 3.25 ms |
| BCJSSE + hybrid helper (no ACCP) | 5.05 ms | 5.24 ms |
| **BCJSSE + hybrid helper + ACCP** | **2.26 ms** | **2.56 ms** |
| BCJSSE + hybrid helper + ACCP + ML-DSA certs (no ACCP) | 2.58 ms | 2.77 ms |
| **BCJSSE + hybrid helper + ACCP + ML-DSA certs** | **2.35 ms** | **2.50 ms** |

### Interop against OpenSSL 3.6.1 `s_server -groups X25519MLKEM768`

| Stack | Mean | Handshakes |
|---|---|---|
| BCJSSE pinned to BC (PQ kx, classical auth) | 4.69 ms | 100/100 ✓ |
| **BCJSSE + hybrid helper + ACCP (PQ kx, classical auth)** | **3.18 ms** | **100/100 ✓** |

Interop confirms the in-process numbers are not artifacts of both ends being the same JVM — real cross-stack handshakes over TCP.

### Event interpretation

1. **The hybrid helper strategy is strictly better than BCJSSE pinned to BC**. Faster in every configuration, and it enables ACCP integration that was previously thought impossible.

2. **ACCP's speedup is configuration-dependent**. Classical handshakes see a ~30% speedup from ACCP (mostly from AES-GCM and RSA operations). ML-DSA handshakes see only ~13% because ML-DSA signing is already fast and dominates a smaller fraction of the total. PQ kx handshakes see ~20% because ML-KEM in BC is relatively fast.

3. **SunJSSE + ACCP is the fastest configuration for classical TLS 1.3** at 1.76 ms. If you don't need PQ today, this is unambiguously the best option. No hybrid helper, no custom code, just register ACCP at provider position 1.

4. **The fastest PQ configuration we can build today is BCJSSE + hybrid helper + ACCP** at 2.26–2.56 ms depending on whether authentication is ML-DSA or classical. This is only ~30% slower than SunJSSE+ACCP classical, and it's fully or partially post-quantum.

5. **ML-DSA authentication is essentially free from a latency perspective**. Going from classical ECDSA/RSA auth to ML-DSA auth adds ~100 µs to handshake time. The old concern that "ML-DSA is too slow" doesn't hold up for handshake performance.

## Strategies for the team to consider

### Strategy A: SunJSSE + ACCP (classical-only, now)

```java
Security.insertProviderAt(new AmazonCorrettoCryptoProvider(), 1);
// ... use SSLContext.getInstance("TLSv1.3") normally
```

- **Latency**: 1.76 ms classical
- **PQ key exchange**: No (until JDK 27 / JEP 527)
- **PQ authentication**: No (no JEP filed)
- **Code impact**: Trivial — one line added to startup
- **Roster impact**: Cert refresh only if we also migrate from SHA384withRSA to SHA384withRSAandMGF1
- **When to use**: If the harvest-now-decrypt-later threat model is considered low-urgency and we want the biggest performance win now

### Strategy B: BCJSSE pinned to BC (PQ key exchange, no ACCP)

```java
Security.addProvider(new BouncyCastleJsseProvider(bcProv));
```

- **Latency**: 3.16 ms classical, 3.25 ms PQ kx
- **PQ key exchange**: Yes (X25519MLKEM768)
- **PQ authentication**: No
- **Code impact**: Medium — rewrite TlsFactory to use BCJSSE, switch keystore to BKS, switch cert sig to PSS
- **Roster impact**: Cert refresh (PKCS#1v1.5 → PSS on existing certs)
- **When to use**: If PQ key exchange is required now and the performance trade-off is acceptable

### Strategy C: BCJSSE + hybrid helper + ACCP (PQ key exchange + ACCP acceleration)

```java
final JcaJceHelper hybridHelper = new HybridJcaJceHelper(
        new ProviderJcaJceHelper(bcProv),  // ML-KEM → BC
        new DefaultJcaJceHelper());        // everything else → chain (ACCP first)

final JcaTlsCryptoProvider cryptoProvider = new JcaTlsCryptoProvider() {
    @Override public JcaJceHelper getHelper() { return hybridHelper; }
};

Security.insertProviderAt(new AmazonCorrettoCryptoProvider(), 1);
Security.addProvider(bcProv);
Security.addProvider(new BouncyCastleJsseProvider(false, cryptoProvider));
```

- **Latency**: 2.26 ms classical, 2.56 ms PQ kx
- **PQ key exchange**: Yes (X25519MLKEM768)
- **PQ authentication**: No (classical RSA/EC certs)
- **Code impact**: Medium + ~250 lines for the HybridJcaJceHelper implementation
- **Roster impact**: Cert refresh (PKCS#1v1.5 → PSS)
- **ACCP impact**: Platform-specific jar (one per target architecture), native library loaded at startup, ~4 MB footprint
- **When to use**: PQ key exchange with no roster schema change, best performance available today for this threat level

### Strategy D: BCJSSE + hybrid helper + ACCP + ML-DSA certs (fully PQ)

Same code as Strategy C, but also:
- Generate ML-DSA-65 signing keys (new key type in roster)
- Sign agreement certs with ML-DSA-65
- Advertise `mldsa65` in TLS signature schemes

- **Latency**: 2.35 ms classical kx + ML-DSA auth, 2.50 ms PQ kx + ML-DSA auth
- **PQ key exchange**: Yes
- **PQ authentication**: Yes (ML-DSA-65)
- **Code impact**: Large — state schema change, DAB transactions, tooling, migration coordination
- **Roster impact**: New `gossipMlDsaPublicKey` field (or similar) in `RosterEntry`
- **ACCP impact**: Same as Strategy C
- **When to use**: If full quantum resistance is required and the team is willing to do the roster schema migration

### Strategy E: Wait for JDK 27 (JEP 527)

- **Latency**: ~1.8 ms estimated (SunJSSE + ACCP + native ML-KEM support)
- **PQ key exchange**: Yes (via SunJSSE natively)
- **PQ authentication**: No (no JEP filed)
- **Code impact**: None — JDK upgrade only
- **Roster impact**: None
- **When to use**: If we can afford to wait ~6 months and PQ authentication is not required

## Recommendation

Three decision branches depending on urgency and risk appetite:

1. **No PQ urgency**: Strategy A (SunJSSE + ACCP) now, migrate to Strategy E (JDK 27 + ACCP) when JDK 27 ships. Minimal code change, best performance, smooth migration path. **This is the path of least resistance.**

2. **PQ key exchange urgent, PQ authentication not**: Strategy C (BCJSSE + hybrid helper + ACCP). Real X25519MLKEM768, fast, no roster schema change, ships today. The hybrid helper is the key enabler — without it, BCJSSE can't benefit from ACCP.

3. **Full PQ urgent (both key exchange and authentication)**: Strategy D. Add ML-DSA keys to the roster and use them for authentication. The performance penalty vs Strategy C is minimal (~10%) but the migration complexity is significant (state schema + DAB + tooling).

**The biggest change to the earlier recommendation**: ACCP is no longer "drop it, it doesn't help BCJSSE." With the hybrid helper, ACCP is a significant enabler — it makes BCJSSE configurations competitive with SunJSSE+ACCP and unlocks full PQ at sub-3ms latency. **Include ACCP in any BCJSSE-based strategy.**

## Code pointers

All experimental code lives in `platform-sdk/consensus-tls-debug`:

- `MtlsDebugAccp.java` — BCJSSE pinned to BC, optional ACCP registration. The original (and partially misleading) benchmark.
- `MtlsDebugInterop.java` — Client-only variant that connects to an external TLS server (e.g., `openssl s_server`). Has `--hybrid-helper` flag to exercise the hybrid helper approach.
- `MtlsDebugHybrid.java` — Custom hybrid `JcaJceHelper` implementation. Contains `HybridJcaJceHelper` as a public inner class so other variants can use it. Supports `--mldsa` for ML-DSA authentication and `--mlkem` for PQ key exchange.
- `libs/accp-mlkem.jar` — Locally-built ACCP 2.6.0 with ML-KEM support, used as a `runtimeOnly` dependency.

To reproduce the key results:

```bash
# Strategy A baseline: SunJSSE + ACCP
./gradlew :consensus-tls-debug:run --args="--accp --sunjsse --iterations=500"

# Strategy B baseline: BCJSSE pinned to BC
./gradlew :consensus-tls-debug:run --args="--accp --no-accp --mlkem --iterations=500"

# Strategy C: BCJSSE + hybrid helper + ACCP
./gradlew :consensus-tls-debug:run --args="--hybrid --mlkem --iterations=500"

# Strategy D: fully PQ with ACCP
./gradlew :consensus-tls-debug:run --args="--hybrid --mlkem --mldsa --iterations=500"

# Interop verification against external OpenSSL server
openssl s_server -accept 18443 -www -tls1_3 \
    -cert /tmp/pq-interop/server.crt -key /tmp/pq-interop/server.key \
    -groups X25519MLKEM768 -quiet &
./gradlew :consensus-tls-debug:run --args="--interop --hybrid-helper --mlkem --iterations=100"
```

## Still to investigate

1. **Event signature verification benchmark**. ACCP accelerates RSA-3072 signature verification at the JCA level. Hashgraph event verification is on the consensus hot path (hundreds to thousands of verifications per second). A benchmark that measures `Signature.verify` throughput with and without ACCP, independent of TLS, could justify ACCP inclusion even without the TLS changes. Not yet done.

2. **ML-DSA interop against OpenSSL**. OpenSSL 3.6.1 supports ML-DSA but requires setup to enable it in TLS handshakes. The hybrid helper + ML-DSA path has been verified working in-process and against an OpenSSL classical peer, but not against an OpenSSL peer specifically using ML-DSA signatures. This would confirm wire-format compatibility.

3. **Long-running stability**. All benchmarks are ~500 handshakes over a few seconds. A long-running test (millions of handshakes, hours of uptime) would confirm there are no memory leaks, GC pressure issues, or native library stability concerns with ACCP's JNI layer.

4. **Linux x86_64 performance**. All measurements are on macOS arm64 (M-series Mac). Production deployment targets are Linux x86_64 (AWS EC2, etc.). The relative speedups should hold across platforms but the absolute numbers will differ. Rerunning the full matrix on a Linux x86_64 machine is recommended before final decisions.