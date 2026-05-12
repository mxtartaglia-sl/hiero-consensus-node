# Post-Quantum TLS Investigation

Comprehensive notes on the investigation into post-quantum TLS for gossip node-to-node connections.

## Executive summary

**Question**: Can we have quantum-secure TLS now, or should we wait?

**Answer**: Yes, we can have partial or full PQ TLS now, at significant cost. The choice depends on threat-model urgency.

- **Partial PQ** (ML-KEM key exchange, classical authentication): solves harvest-now-decrypt-later. Requires a framework migration from SunJSSE to BCJSSE plus a certificate-refresh roster update. Can ship without a roster schema change. **Proven end-to-end in production gossip with hybrid `X25519MLKEM768` key exchange.**
- **Full PQ** (ML-KEM + ML-DSA): solves both harvest-now-decrypt-later and real-time quantum impersonation. Requires everything in partial PQ plus a new PQ key type in the roster (state schema change, DAB transaction updates, tooling changes, coordinated rollout).
- **Wait for JDK 27**: JEP 527 adds ML-KEM key exchange to SunJSSE natively. No code changes, but only addresses key exchange. ML-DSA authentication has no JEP filed.

**Key finding**: SunJSSE has ML-DSA and ML-KEM at the JCA layer (JDK 25 has them via SunJCE), but **does not wire either into its TLS handshake code**. BCJSSE is currently the only JSSE provider that supports PQ in TLS 1.3 handshakes.

---

## Background: How TLS works

A TLS 1.3 handshake has three independent phases:

### 1. Key exchange
Derives a shared secret that will be used to encrypt the session. In TLS 1.3 this uses ephemeral keys, never the certificate keys.

- **Classical**: x25519, secp256r1, secp384r1 (ECDHE)
- **Hybrid PQ**: X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024
- **Pure PQ**: MLKEM512, MLKEM768, MLKEM1024

The keys in `key_share` extensions are generated fresh on every handshake and discarded after. This is the source of forward secrecy.

### 2. Authentication
Each side proves its identity by presenting a certificate and signing a `CertificateVerify` message with the certificate's private key. The peer verifies:

1. The certificate chain validates against a trust anchor (PKIX path validation)
2. The `CertificateVerify` signature verifies against the certificate's public key

The signatures here are where RSA / ECDSA / Ed25519 / ML-DSA come in. **This is the quantum-vulnerable part for authentication**.

### 3. Symmetric encryption
AES-256-GCM (or similar) encrypts the actual traffic using keys derived from the key exchange shared secret. Symmetric crypto is considered quantum-safe — Grover's algorithm provides at most a quadratic speedup, so 256-bit AES still gives ~128-bit quantum security.

### Threat model implications

- **Harvest-now-decrypt-later**: attacker records encrypted traffic today, decrypts it in 2035 after breaking x25519. Solved by ML-KEM in key exchange.
- **Real-time impersonation**: attacker with a live quantum computer during a handshake forges a `CertificateVerify` signature, impersonates a peer, MITMs the connection. Solved only by PQ signatures (ML-DSA) in authentication.

Our traffic becomes public at consensus time, so harvest-now-decrypt-later is less urgent for us than for, say, messaging apps. But real-time impersonation would break consensus integrity whenever quantum attacks become viable.

---

## Current gossip TLS setup (baseline)

As of the start of this investigation, the `tls13` branch has TLS 1.3 with SunJSSE:

- **Protocol**: TLSv1.3
- **Cipher suite**: `TLS_AES_256_GCM_SHA384`
- **Key exchange**: `x25519` (set explicitly via `SSLParameters.setNamedGroups`)
- **Provider**: SunJSSE (default Java)
- **KMF/TMF**: `SunX509`
- **Keystore format**: `PKCS12`
- **Signing keys**: RSA-3072, stored on disk as `.pfx` or `s-private-*.pem`
- **Agreement keys**: EC-384 (P-384 / secp384r1), generated in memory on node startup (never persisted)
- **Certificate signature algorithm**: `SHA384withRSA` (PKCS#1 v1.5)
- **Trust model**: signing certs loaded from the roster (`gossipCaCertificate` field), built into a `TrustManager`. Agreement certs are ephemeral, signed by the signing key at startup, and verified during each handshake via PKIX path validation.

### How peer authentication works at handshake time

1. Node A connects to Node B
2. Both sides send their agreement cert in the TLS `Certificate` message
3. Each side computes a `CertificateVerify` signature over the handshake transcript using its agreement key
4. Each side verifies the peer's:
   - Certificate chain (presented `[agrCert]` or `[agrCert, sigCert]`, verified against the trust store's sigCert by RSA signature verification)
   - `CertificateVerify` signature using the public key from the received agrCert

The RSA verification in step 4a is **load-bearing**. It's what binds the ephemeral agrCert to a trusted node identity. We verified this empirically (see "Corrupted signature test" below).

---

## Debug tool: `consensus-tls-debug` module

A standalone Gradle module was built to run mTLS handshakes outside of gossip, so each TLS configuration could be tested in isolation. It lives at `platform-sdk/consensus-tls-debug/`.

### Variants built

| Flag | Class | Provider | Key exchange | Auth key | Cert sig | Status |
|---|---|---|---|---|---|---|
| *(default)* | `MtlsDebug` | BCJSSE | x25519 | EC-384 | SHA384withECDSA | ✅ Works |
| `--java` | `MtlsDebugJava` | SunJSSE | x25519 | EC-384 | SHA384withRSA | ✅ Works |
| `--mlkem` | `MtlsDebugMlKem` | BCJSSE | X25519MLKEM768 | EC-384 | SHA384withECDSA | ✅ Works |
| `--mlkem --pure` | `MtlsDebugMlKem` | BCJSSE | MLKEM768 | EC-384 | SHA384withECDSA | ✅ Works |
| `--mlkem-java` | `MtlsDebugMlKemJava` | SunJSSE | X25519MLKEM768 | EC-384 | SHA384withRSA | ❌ Fails (SunJSSE silently drops X25519MLKEM768) |
| `--pq` | `MtlsDebugPq` | BCJSSE | X25519MLKEM768 | ML-DSA-65 | ML-DSA-65 | ✅ Works |
| `--pq --pure` | `MtlsDebugPq` | BCJSSE | MLKEM768 | ML-DSA-65 | ML-DSA-65 | ✅ Works |
| `--pq-java` | `MtlsDebugPqJava` | SunJSSE | x25519 | ML-DSA-65 | ML-DSA-65 | ❌ Fails (SunJSSE silently drops mldsa65) |
| `--pq-ec-ca` | `MtlsDebugPqEcCa` | BCJSSE | X25519MLKEM768 | ML-DSA-65 (EC CA signs cert) | SHA384withECDSA | ✅ Works |
| `--rsa-pss` | `MtlsDebugRsaPss` | BCJSSE | x25519 | RSASSA-PSS-2048 | SHA256withRSAandMGF1 | ✅ Works |
| `--gossip-pss` | `MtlsDebugGossipPss` | BCJSSE | x25519 | EC-384 | SHA384withRSAandMGF1 | ✅ Works — proves EC+RSA gossip setup works with only PSS change |
| `--ecdh-test` | `MtlsDebugEcdhTest` | BCJSSE | (test only) | — | — | Isolation test |
| `--psk` | `MtlsDebugPsk` | BC raw TLS | x25519 (ephemeral) | None (PSK) | None | ✅ Works (bypasses JSSE) |
| `--rogue-ca` | `MtlsDebug` with rogue flag | BCJSSE | x25519 | EC-384 (rogue CA) | SHA384withECDSA | ❌ Fails as expected — trust store wins |
| `--java --corrupt` | `MtlsDebugJava` with flag | SunJSSE | x25519 | EC-384 (corrupted sig) | SHA384withRSA | ❌ Fails as expected — proves signature is checked |

---

## Findings

### Finding 1: SunJSSE TLS 1.3 "just works" with the current gossip key setup

The `--java` variant mirrors gossip's main branch exactly: RSA-3072 CA, EC-384 agreement keys, SHA384withRSA certs, PKCS12 keystore, SunJSSE provider, TLS 1.3. It works with zero workarounds.

**Conclusion**: the prerequisite TLS 1.3 migration is trivial on SunJSSE. This has already been done on the `tls13` branch.

### Finding 2: BCJSSE does NOT work with the gossip key setup out of the box

When we first tried BCJSSE with EC-384 agreement keys + RSA-signed certs, we hit three apparent failures. After investigation, only two were real:

#### Failure 1 (false alarm): ECDH in disabled algorithms

**Hypothesis**: JDK 21+ has `ECDH` in `jdk.tls.disabledAlgorithms`. BCJSSE reads this and filters out all ECDSA signature schemes.

**Workaround applied**: patch `Security.setProperty("jdk.tls.disabledAlgorithms", ...)` before loading BCJSSE to remove `ECDH`.

**Result of isolation test** (`--ecdh-test`): **FALSE ALARM**. With the ECDH disable left in place but `secp384r1` added to `namedGroups`, ECDSA signature schemes still appear in the ClientHello. The ECDH entry does NOT block ECDSA.

We were fooled because we applied multiple fixes simultaneously and attributed the success to the wrong one.

#### Failure 2 (real): Named groups gate signature schemes

BCJSSE's `SignatureSchemeInfo.isNamedGroupOK` couples TLS 1.3 ECDSA signature schemes to the presence of their named curve in the `namedGroups` list:

```java
// For ecdsa_secp384r1_sha384:
return post13Allowed && NamedGroupInfo.hasLocal(namedGroupInfos, secp384r1);
```

If `secp384r1` is not in the configured named groups, `ecdsa_secp384r1_sha384` is silently filtered out of the ClientHello's `signature_algorithms` extension. The server then cannot find a matching credential for the peer's EC agrCert.

SunJSSE does not do this coupling — named groups only control key exchange in SunJSSE.

**Fix**: include `secp384r1` alongside the key exchange group (`x25519` or `X25519MLKEM768`) in `namedGroups`. Even if the actual key exchange uses the first-listed group, `secp384r1` acts as a "signal" for BCJSSE to enable ECDSA with P-384.

#### Failure 3 (real): PKCS#1 v1.5 RSA rejected in cert chains

BCJSSE's `ProvAlgorithmChecker.checkChain` validates the certificate chain's signature algorithms against the per-connection signature constraints. For TLS 1.3, BCJSSE rejects `SHA384withRSA` (PKCS#1 v1.5) as "not permitted with given parameters" because TLS 1.3 requires RSA-PSS for RSA signatures.

**Confirmed with stack trace**:
```
java.security.cert.CertPathValidatorException:
  Signature algorithm 'SHA384withRSA' not permitted with given parameters
  at ProvAlgorithmChecker.checkIssued
  at ProvAlgorithmChecker.checkChain
  at ProvX509KeyManager.isSuitableChain
```

SunJSSE does not apply TLS 1.3 signature restrictions to cert chains — it only enforces them on the `CertificateVerify` message.

**Fix**: change the cert signing algorithm from `SHA384withRSA` (PKCS#1 v1.5) to `SHA384withRSAandMGF1` (RSA-PSS). Same RSA keys, just different padding during signing. Proven in `--gossip-pss` variant.

### Finding 3: Minimal BCJSSE migration for gossip

From findings 1–3, the minimal changes needed to make BCJSSE work with the existing gossip key setup are:

1. Register BCJSSE provider (passing the BC provider instance explicitly — see finding 6)
2. Change KMF/TMF type from `SunX509` to `PKIX` (BCJSSE)
3. Change keystore type from `PKCS12` to `BKS` (BCJSSE native)
4. Include both the agreement cert AND the CA cert in the keystore key entry chain (BCJSSE's PKIX KeyManager does pre-flight chain validation)
5. Add `secp384r1` to the named groups list alongside the key exchange group
6. Set signature schemes explicitly on the `SSLParameters` (BCJSSE requires them to be listed)
7. **Change cert signature from `SHA384withRSA` to `SHA384withRSAandMGF1`** — this is the most invasive change because it changes the DER bytes of every cert, invalidating existing on-disk and in-state copies

No key type changes. No algorithm family changes. RSA-3072 signing keys and EC-384 agreement keys are unchanged.

### Finding 4: The gossip trust model actually verifies the RSA signature

Leemon's question: "are we relying on the cert signature for security?"

Two empirical tests confirmed the answer is **yes**:

#### Corrupted signature test (`--java --corrupt`)

We flipped one byte in the agreement cert's signature, leaving everything else intact. The handshake fails with:

```
javax.net.ssl.SSLHandshakeException: (certificate_unknown) Certificate signature validation failed
  at sun.security.ssl.CertificateMessage$T13CertificateConsumer.checkServerCerts
  at sun.security.ssl.X509TrustManagerImpl.checkServerTrusted
  at sun.security.validator.SimpleValidator.engineValidate
```

This proves the framework is actually verifying the RSA signature (not just accepting certs by presence in a trust store).

#### Rogue CA test (`--rogue-ca`)

We generated two CAs with the same subject DN (`CN=DebugCA`). Signed the agreement certs with the rogue CA. Put the rogue CA cert in the keystore chain. Kept the legit CA in the trust store. The handshake fails:

```
org.bouncycastle.tls.TlsFatalAlert: certificate_unknown(46)
Caused by: java.security.cert.CertificateException: Unable to construct a valid chain
```

This proves that the trust store is the ground truth — not the CA cert presented in the chain. The framework uses the trust store's public key to verify the signature on the end-entity cert, ignoring any fake CA cert the peer tries to pass off.

**Implication for Leemon's question**: the current design IS in "verify signatures" mode, not "trust cert if it matches state" mode. The cert presented at handshake (the agreement cert) is NOT in state — it's ephemeral. The signing cert IS in state, but it's only the trust anchor, and the framework verifies the agrCert's RSA signature against the sigCert's public key on every handshake. A quantum attacker breaking RSA could forge agrCert signatures and impersonate nodes in real time.

### Finding 5: Why separate signing and agreement keys?

The current design has:

- **Signing key** (RSA-3072): long-lived, stored on disk, also used to sign consensus events
- **Agreement key** (EC-384): ephemeral, regenerated on every node startup, used only for TLS handshakes

The claimed security benefit is **forward secrecy of identity**: if a node's memory is compromised at time T, the attacker can only impersonate the node until the next restart (since the agrKey is regenerated). In practice this is narrow — any memory disclosure attack that grabs the agrKey almost certainly also grabs the sigKey (both sit in the JVM heap).

Other benefits of the separation:

- The TLS code path doesn't directly handle the sigKey, so TLS library bugs have a smaller blast radius
- The agrKey is EC-384 (smaller, faster signatures for TLS handshakes); the sigKey is RSA-3072 (faster verification for event signatures)
- Different algorithms for different workloads

The separation is defensible but not load-bearing for security. Unifying them is a legitimate architectural option if the simplification benefit outweighs the marginal blast-radius loss.

### Finding 6: BCJSSE silently breaks ML-KEM if given the wrong JCA helper

When we first tried `--pq` (ML-KEM key exchange), BCJSSE silently disabled `X25519MLKEM768` with log line:

```
WARNING: 'SSLParameters.namedGroups' contains disabled NamedGroup: X25519MLKEM768
```

Root cause: BCJSSE's `JcaTlsCrypto` uses a `JcaJceHelper` to find JCA primitives. The default (`DefaultJcaJceHelper`) searches the global provider chain. On JDK 25, the global search finds JDK's SunJCE ML-KEM implementation before BC's. The JDK's `KeyPairGenerator.initialize(MLKEMParameterSpec.fromName("ML-KEM-768"))` rejects BC's `MLKEMParameterSpec` — different classes. `KemUtil.isKemSupported` catches the exception and returns `false`, and BCJSSE silently disables the entire `X25519MLKEM768` named group.

**Fix**: pass the BC provider explicitly to BCJSSE's constructor:
```java
final BouncyCastleProvider bcProv = new BouncyCastleProvider();
Security.addProvider(bcProv);
Security.addProvider(new BouncyCastleJsseProvider(bcProv));
```

This pins BCJSSE's `JcaTlsCrypto` to use BC for all primitive lookups, avoiding the SunJCE collision.

### Finding 7: SunJSSE does not support ML-KEM named groups (JDK 25)

Attempted `MtlsDebugMlKemJava`: set `X25519MLKEM768` via `SSLParameters.setNamedGroups()`. SunJSSE silently drops it:

```
SupportedGroupsExtension: Ignore unspecified named group: X25519MLKEM768
WARNING: no available named group
```

The `setNamedGroups` API accepts the string without error, but SunJSSE has a hardcoded internal enum of recognized groups. Unrecognized entries are filtered out when building the ClientHello.

**JDK 27 / JEP 527** will add `X25519MLKEM768`, `SecP256r1MLKEM768`, and `SecP384r1MLKEM1024` to SunJSSE, with `X25519MLKEM768` enabled by default. Available in JDK 27 early access build 6+.

### Finding 8: SunJSSE does not support ML-DSA signature schemes (JDK 25)

Attempted `MtlsDebugPqJava`: set `mldsa65` via `SSLParameters.setSignatureSchemes()`. SunJSSE silently drops it from the ClientHello's `signature_algorithms` extension. The list sent to the server only contains classical schemes:

```
[ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, ecdsa_secp521r1_sha512,
 ed25519, ed448,
 rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512,
 rsa_pss_pss_sha256, rsa_pss_pss_sha384, rsa_pss_pss_sha512]
```

No `mldsa*`. Same mechanism as finding 7 — hardcoded enum, silent drop.

**No JEP filed for ML-DSA in SunJSSE as of early 2026**. JEP 527 covers only key exchange.

### Finding 9: JDK 25 has ML-KEM and ML-DSA at the JCA layer

JDK 25's SunJCE registers:

- `KEM.ML-KEM`, `KEM.ML-KEM-512`, `KEM.ML-KEM-768`, `KEM.ML-KEM-1024`
- `KeyFactory.ML-KEM*`, `KeyPairGenerator.ML-KEM*`
- `Signature.ML-DSA*`, `KeyFactory.ML-DSA*`, `KeyPairGenerator.ML-DSA*`

You can generate PQ keys and sign arbitrary data with JDK 25 out of the box. The gap is only at the JSSE layer — TLS handshake code doesn't know about these schemes.

### Finding 10: BCJSSE does not support PSK mode in JSSE

For the theoretical alternative "skip the signature check entirely, use TLS-PSK with a shared secret from the roster":

- BCJSSE's TLS 1.3 PSK code is all `TODO[tls13]`. Maintainer confirmed in [bc-java#1884](https://github.com/bcgit/bc-java/issues/1884) that PSK is not supported in BCJSSE.
- BC's low-level TLS API (`TlsClientProtocol` / `TlsServerProtocol` with `BasicTlsPSKExternal`) DOES support PSK for TLS 1.3. We built a proof-of-concept (`--psk`) that works with raw BC TLS, bypassing JSSE entirely.
- The cost of adopting this path: gossip's entire TLS abstraction (`TlsFactory`, `SSLSocket` / `SSLServerSocket`, inbound/outbound connection handlers) would need to be rewritten to use raw BC TLS instead of JSSE. Not a drop-in replacement.

### Finding 11: Ed25519 is a better classical signing key than RSA-3072

Comparison:

| Algorithm | Classical security | Quantum-safe? | Sig size | Public key size | Signing speed |
|---|---|---|---|---|---|
| RSA-3072 | ~128 bits | No | 384 bytes | 384 bytes | slow |
| P-384 (ECDSA) | ~192 bits | No | ~96 bytes | 48 bytes | fast |
| Ed25519 | ~128 bits | No | 64 bytes | 32 bytes | very fast |
| ML-DSA-65 | — | **Yes** | ~3,300 bytes | ~2,000 bytes | moderate |

Ed25519's advantages over RSA-3072:
- Deterministic nonces (no RNG-related failure mode like ECDSA)
- No invalid curve attacks (Edwards curves are complete)
- Constant-time by design
- Much smaller keys and signatures
- Already supported in `SigningSchema.ED25519` enum in the codebase — infrastructure exists

Ed25519 is NOT part of CNSA Suite 1.0 but IS in FIPS 186-5 (2023). If not targeting CNSA compliance, Ed25519 is superior to RSA-3072 for the signing key role.

None of these are quantum-safe. A classical Ed25519 upgrade is an incremental win but doesn't change the PQ story.

---

## Production gossip migration: proven working

The BCJSSE migration was applied to the actual gossip code (not just the debug module) and run successfully end-to-end with ML-KEM hybrid key exchange.

### Code changes

1. **`CryptoConstants.java`**:
   - `SIG_TYPE2`: `SHA384withRSA` → `SHA384withRSAandMGF1`
   - `KEY_MANAGER_FACTORY_TYPE`: `SunX509` → `PKIX`, added `KEY_MANAGER_FACTORY_PROVIDER = "BCJSSE"`
   - `TRUST_MANAGER_FACTORY_TYPE`: `SunX509` → `PKIX`, added `TRUST_MANAGER_FACTORY_PROVIDER = "BCJSSE"`
   - `KEYSTORE_TYPE`: `pkcs12` → `BKS`, added `KEYSTORE_PROVIDER = "BC"`
   - Added `SSL_PROVIDER = "BCJSSE"`
   - Added `TLS_NAMED_GROUPS = {"X25519MLKEM768", "secp384r1"}`
   - Added `TLS_SIGNATURE_SCHEMES = {ecdsa_secp384r1_sha384, ecdsa_secp256r1_sha256, ed25519, ed448, rsa_pss_rsae_sha256, rsa_pss_rsae_sha384}`
   - Registered BCJSSE provider with explicit BC reference: `new BouncyCastleJsseProvider(bcProv)`

2. **`ConsensusCryptoUtils.java`**:
   - `createKeyManagerFactory` now takes a `caCertificate` parameter
   - Uses BKS keystore with cert chain `[agrCert, caCert]`
   - Uses BCJSSE PKIX KMF

3. **`TlsFactory.java`**:
   - Constructor takes additional `sigCert` parameter
   - Uses `BCJSSE` for SSLContext and TMF
   - Configures `namedGroups` and `signatureSchemes` on server and client sockets

4. **`NetworkUtils.java`**:
   - Passes `sigCert()` to TlsFactory constructor

5. **`consensus-utility/module-info.java`**:
   - Added `requires org.bouncycastle.tls`

6. **`TlsFactoryTest.java`**:
   - Updated constructor calls with mock `sigCert`

### Data changes (required for the running network)

Because `SIG_TYPE2` changed, every node's sigCert (signed self-signed by the signing key) has different DER bytes. This requires:

1. **Regenerate local keys** via `pcli generate-keys` — produces new `s-public-*.pem` / `s-private-*.pem` files signed with RSA-PSS
2. **Update `gossipCaCertificate` in state** — the new cert DER bytes must replace the old ones in the roster. For dev testing, this means editing `genesis-network.json`:
   ```bash
   openssl x509 -in data/keys/s-public-node1.pem -outform DER | base64 | tr -d '\n'
   ```
   And pasting the result into both `rosterEntry.gossipCaCertificate` and `node.gossipCaCertificate` fields.

### Debugging issues encountered

- The node was rejecting its own cert chain with `CertPathValidatorException: Signature algorithm 'SHA384WITHRSA' not permitted with given parameters`. Root cause: the regenerated sigCert on disk was PSS, but `genesis-network.json` still had the old PKCS#1 v1.5 blob. Updating the genesis network file fixed it.
- BCJSSE was not accessible to reflection from our module for the logging helper. Required `--add-opens=org.bouncycastle.tls/org.bouncycastle.tls=org.hiero.consensus.gossip.impl`.

### Validation

Once keys and genesis file were regenerated consistently:

```
[TLS server] protocol=TLSv1.3 suite=TLS_AES_256_GCM_SHA384 namedGroup=clientGroups=[X25519MLKEM768,secp384r1] ...
```

`tshark` capture confirmed the key_share sizes in ClientHello (1408 bytes) and ServerHello (1271 bytes) match X25519MLKEM768 (x25519 32 bytes + ML-KEM-768 public key 1184 bytes client-side, x25519 32 bytes + ML-KEM-768 ciphertext 1088 bytes server-side).

**This proves the end-to-end path works in production gossip**: TLS 1.3 + BCJSSE + X25519MLKEM768 hybrid PQ key exchange + classical (EC-384) authentication, using existing RSA-3072 signing keys.

---

## Performance impact

### Final benchmark results (measured, corrected, verified)

Measured on macOS arm64 with the `MtlsDebugAccp` and `MtlsDebugInterop` variants. Three trials per configuration, 500 iterations each, 50 warmup, results consistent within ~10%. PQ configurations verified end-to-end against OpenSSL 3.6.1's `s_server -groups X25519MLKEM768`.

**In-process (BCJSSE client + BCJSSE server, same JVM):**

| Stack | Mean latency | Throughput |
|---|---|---|
| SunJSSE classical (baseline) | 5.64 ms | 177 hs/sec |
| BCJSSE classical (pinned to BC) | 3.16 ms | 316 hs/sec |
| BCJSSE hybrid PQ (X25519MLKEM768) | 3.25 ms | 308 hs/sec |

**Interop against OpenSSL 3.6.1 `s_server -groups X25519MLKEM768`:**

| Stack | Mean latency | Throughput |
|---|---|---|
| BCJSSE classical client (baseline) | ~5 ms est. | — |
| BCJSSE hybrid PQ client | 4.69 ms | 213 hs/sec |

### Key findings

1. **BCJSSE pinned to BC is ~44% faster than SunJSSE for classical handshakes** (3.16 ms vs 5.64 ms on this hardware). This is the opposite of the earlier-reported ~7% regression and settles the "performance cost of migrating to BCJSSE" concern.

2. **Hybrid PQ key exchange adds only ~3% latency vs classical** when pinned to BC (3.25 ms vs 3.16 ms). ML-KEM's cost is much smaller than expected — BC's pure-Java ML-KEM-768 is actually fast. The earlier "52% PQ overhead" number was from a different baseline where BCJSSE used `DefaultJcaJceHelper`.

3. **BCJSSE+ACCP does NOT speed up BCJSSE when pinned to BC**. When `new BouncyCastleJsseProvider(bcProv)` is used, BCJSSE's internal `ProviderJcaJceHelper` goes directly to BC for all crypto lookups. The global provider chain (where ACCP is registered at position 1) is never walked. ACCP's accelerated RSA/ECDH/AES-GCM primitives are not invoked.

4. **BCJSSE must be pinned to BC to enable real X25519MLKEM768.** With `DefaultJcaJceHelper`, BCJSSE's `KemUtil.getKeyPairGenerator("ML-KEM")` walks the global provider chain and finds whichever provider registered `KeyPairGenerator.ML-KEM` first. On JDK 25 that could be SunJCE, BC, or a locally-built ACCP with ML-KEM. When `KemUtil` then calls `keyPairGenerator.initialize(BC's MLKEMParameterSpec)`, implementations other than BC's reject the foreign parameter spec class with `InvalidAlgorithmParameterException`. `KemUtil.isKemSupported` catches this, returns `false`, and BCJSSE silently disables the `X25519MLKEM768` named group.

5. **Even locally-built ACCP with ML-KEM is incompatible with BCJSSE**. We built ACCP 2.6.0 from source with `-DTARGET_JDK_VERSION=17`, confirmed it registers `KEM.ML-KEM-768` and `KeyPairGenerator.ML-KEM-*` via JCA, then tried to use it with BCJSSE's `DefaultJcaJceHelper`. Same `disabled NamedGroup` warning, same interop failure — ACCP's `MLKEMParameterSpec` class isn't BC's. The only way to make BCJSSE's ML-KEM work is to pin BCJSSE to BC.

### Earlier invalid measurements — retracted

The earlier version of this document reported that "BCJSSE + ACCP is ~50% faster than SunJSSE" and "ACCP makes ML-KEM free." Both claims were based on measurements with BCJSSE in an unpinned configuration, where:

- The "BCJSSE + ACCP" benchmark with `--mlkem` was silently falling back to `secp384r1` classical ECDH instead of using X25519MLKEM768. The 2.4 ms "PQ + ACCP" number was really accelerated-classical, not PQ.
- The comparison between "BCJSSE + ACCP classical" (2.4 ms) and "BCJSSE without ACCP classical" (4.84 ms) was distorted because the unpinned helper adds per-lookup overhead vs the pinned helper.

When BCJSSE is properly pinned to BC (required for X25519MLKEM768 to work at all), ACCP doesn't get a chance to accelerate anything. The correct comparison is:

- BCJSSE pinned to BC + classical: **3.16 ms** (fast — no chain walk overhead)
- BCJSSE pinned to BC + PQ: **3.25 ms** (fast — PQ cost is minimal in BC's implementation)

### Implications for the team

1. **The "BCJSSE has a ~7% performance regression vs SunJSSE" concern is moot.** BCJSSE pinned to BC is significantly *faster* than SunJSSE on the same hardware. Migration to BCJSSE for PQ support should not be blocked on performance grounds.

2. **ACCP does not accelerate BCJSSE TLS handshakes** in any configuration we've tested. Bundling ACCP with BCJSSE adds platform-specific deployment complexity for no measurable benefit in the handshake path. **Drop ACCP from the BCJSSE migration plan.**

3. **ACCP may still be valuable elsewhere** — event signature generation/verification, which goes through JCA (`Signature.getInstance`) directly rather than through BCJSSE. That's a separate benchmark (not done yet) and could still justify including ACCP, but not for TLS reasons.

4. **BCJSSE must be pinned to BC in production code** (`new BouncyCastleJsseProvider(bcProv)`). Any configuration that lets BCJSSE walk the default provider chain will silently disable ML-KEM when JDK 25+ SunJCE or ACCP registers an incompatible ML-KEM implementation ahead of BC.

### Verified via OpenSSL interop

The BCJSSE-pinned-to-BC configuration was verified end-to-end against an external OpenSSL server running `openssl s_server -groups X25519MLKEM768`, which rejects any handshake that doesn't use that specific named group. 100 handshakes completed successfully at 4.69 ms mean latency, proving:

- BCJSSE's X25519MLKEM768 implementation is wire-compatible with OpenSSL's
- AWS-LC's ML-KEM primitives (as used via OpenSSL's implementation, which is BoringSSL-derived) agree with BC's ML-KEM primitives on the over-the-wire format
- Our Java-side PQ TLS will interoperate with any other production TLS 1.3 stack that implements RFC 9710 / draft-kwiatkowski-tls-ecdhe-mlkem

---

## Trust model analysis

### Current state

```
Roster:
  gossipCaCertificate (= sigCert, self-signed RSA-3072, long-lived)

On-disk:
  s-private-*.pem (= sigKey, RSA-3072)

In-memory only (regenerated on startup):
  agrKey (EC-384)
  agrCert (signed by sigKey with SHA384withRSAandMGF1)
```

### Handshake trust flow

1. Peer presents agrCert chain `[agrCert]` (and optionally sigCert)
2. Receiving node's TrustManager:
   - Looks up the sigCert with matching subject DN in the trust store (built from the roster)
   - Verifies `agrCert.signature == RSA.sign(sigCert.publicKey, agrCert.tbsBytes)` — this is the load-bearing RSA check
   - If valid, treats agrCert's key as trusted
3. Receiving node verifies `CertificateVerify` signature over the handshake transcript using agrCert.publicKey
4. Both steps succeed → handshake continues

The crucial insight: the sigCert in the trust store is the **trust anchor**, and its own self-signature is NOT verified (PKIX convention — trust anchors are trusted absolutely). But the agrCert is NOT a trust anchor — it's an intermediate, and its signature IS verified against the trust anchor's public key.

### Options to make this post-quantum

**Option A: PQ signing key in roster (ML-DSA)**

Replace or supplement the RSA sigKey with an ML-DSA sigKey. agrCert is signed with ML-DSA. TLS handshake verifies ML-DSA signature using the roster's ML-DSA public key.

- Requires: roster schema change, DAB transaction updates, tooling, migration
- Preserves current architecture (ephemeral agrKey, state-anchored sigKey)

**Option B: Put agrCert (or hash) in state, make agrKey persistent**

Store the agrCert directly in the roster. Custom TrustManager byte-matches presented cert against state instead of PKIX validation.

- Requires: agrKey becomes persistent (on-disk, not regenerated), state update on rotation, custom TrustManager
- Preserves key type separation
- No PQ signature needed — authentication is "match bytes against state"
- **But TLS 1.3 still requires `CertificateVerify`** which uses RSA/ECDSA on the agrKey. So option B alone doesn't eliminate PQ signature exposure unless you also make the agrKey PQ.

**Option C: Unify sigKey and agrKey (use sigKey directly as TLS identity)**

Drop the separate agrKey entirely. sigCert becomes the TLS cert. Custom TrustManager byte-matches sigCert against the roster.

- Requires: custom TrustManager, dropping the ephemeral key layer
- Simplest change — no new fields in roster
- sigKey now used for TLS handshakes, slightly wider attack surface
- Still RSA — CertificateVerify uses sigKey. PQ signature needed to fully eliminate quantum exposure.

**Option D: TLS-PSK with roster-derived secrets**

Bypass certificates entirely. Derive a PSK from roster material (e.g., ML-KEM encapsulation using roster keys). Use TLS-PSK mode.

- Requires: rewriting gossip's TLS abstraction to use raw BC TLS (BCJSSE doesn't support PSK)
- No signatures at all — authentication via PSK knowledge
- Largest architectural change
- Fully PQ if the PSK derivation is PQ

---

## ACCP experiment (complete)

### Background

Amazon Corretto Crypto Provider (ACCP) is a JCA-level provider that replaces classical operations (RSA, ECDH, AES-GCM, etc.) with AWS-LC-backed implementations. It does NOT provide a JSSE/TLS layer — it only accelerates JCA primitives. BCJSSE, when configured with `DefaultJcaJceHelper` (no explicit provider), walks the global JCA provider chain for its crypto lookups, so registering ACCP before BC transparently speeds up BCJSSE's classical operations.

### Setup

- Version: `software.amazon.cryptools:AmazonCorrettoCryptoProvider:2.5.0:osx-aarch_64`
- Provider registration order: `ACCP → BC → BCJSSE (default helper)`
- BCJSSE uses default helper (no explicit provider), so it walks the chain
- ML-KEM operations fall through to BC (ACCP doesn't register ML-KEM in its default artifact)
- Benchmark: `MtlsDebugAccp` variant with `--iterations=500 --warmup=50`
- Hardware: macOS arm64

### Results

| Scenario | No ACCP | With ACCP | Speedup |
|---|---|---|---|
| Classical key exchange (x25519) | 5.1 ms | 2.4–2.6 ms | **~50%** faster |
| Hybrid PQ key exchange (X25519MLKEM768) | 7.7 ms | 2.4 ms | **~69%** faster |
| Throughput, classical | 196 hs/sec | ~400 hs/sec | **+100%** |
| Throughput, hybrid PQ | 130 hs/sec | 416 hs/sec | **+220%** |

Each measurement is the mean of 500 handshakes after 50 warmup iterations. Trial-to-trial variance is small (~5%).

### Key findings

1. **ACCP eliminates the BCJSSE performance regression**. The previously measured ~7% latency gap when migrating from SunJSSE to BCJSSE is fully recovered (and then some). A BCJSSE + ACCP migration would likely be faster than the SunJSSE baseline.

2. **ACCP erases the ML-KEM cost at the handshake layer**. Without ACCP, hybrid PQ key exchange is ~51% slower than classical (7.7 ms vs 5.1 ms) because ML-KEM operations run in pure-Java BC. With ACCP accelerating the classical portions, total handshake time becomes the same as or slightly faster than classical (2.4 ms in both cases). **Adopting ML-KEM becomes essentially free at the handshake-latency level** when ACCP is in the mix.

3. **No correctness issues**. ACCP at position 1, BC fills in for what ACCP doesn't provide. BCJSSE's TLS 1.3 handshake completes successfully with both classical and hybrid PQ key exchange. No code changes to BCJSSE configuration required beyond the provider registration.

### Caveats

- **Platform-specific artifact**. ACCP ships with classifiers per platform: `osx-aarch_64`, `osx-x86_64`, `linux-x86_64`, `linux-aarch_64`. Production deployments need to pull the right one.
- **Global provider chain side effects**. Because BCJSSE uses the default helper to walk the provider chain, ACCP intercepts ALL JCA operations in the process, not just TLS. This affects event signature generation/verification too. Measurement pending separately.
- **Native library loading**. ACCP loads a native library at startup via `System.load`, triggering a JPMS native-access warning. Not an error but needs `--enable-native-access=ALL-UNNAMED` to silence.
- **License**. Apache 2.0 — compatible.
- **Supply chain**. ACCP's underlying crypto comes from AWS-LC (Amazon's fork of BoringSSL). Production-hardened, FIPS-certified, but adds a new dependency.

---

## Decision matrix for the team

### Path comparison

| Path | Key exchange PQ | Auth PQ | Roster data change | Roster schema change | Code change | Tooling change | Wait time |
|---|---|---|---|---|---|---|---|
| (1) Wait for JDK 27 | ✅ (SunJSSE) | ❌ | Cert refresh | No | None | None | ~late 2026 |
| (2) BCJSSE + classical auth | ✅ | ❌ | Cert refresh | No | Large (TlsFactory, KeyStore, config) | Minor | Now |
| (3) BCJSSE + ML-DSA auth | ✅ | ✅ | Cert refresh + new field | **Yes** | Large + new auth path | Large (pcli, migration, DAB txns) | Now (with more work) |
| (4) Unify sigKey as TLS key, byte-match | ✅ (with BCJSSE) | ❌* | Cert refresh if sig algo changes | No | Large | Minor | Now |
| (5) TLS-PSK with ML-KEM-derived secrets | ✅ | ✅ | Maybe (depends on PSK source) | Possibly | Very large (gossip rewrite away from JSSE) | Large | Now |

*(4) isn't PQ for authentication unless sigKey is also made PQ, which then hits the same tooling burden as (3).*

### Key blockers by path

- **(1)**: waiting exposes us to harvest-now-decrypt-later in the interim. No ML-DSA ever (no JEP filed).
- **(2)**: ~7% latency impact measured. No impact on "real-time quantum impersonation" threat model.
- **(3)**: full PQ but largest blast radius — touches state, DAB, tooling, migration coordination.
- **(4)**: architectural simplification, not PQ without also upgrading the sigKey.
- **(5)**: completely different TLS abstraction. Biggest rewrite.

### Leemon's position

- Does not want (2) without (3). Partial PQ alone is not acceptable.
- Has indicated the signature check is probably not load-bearing (disproven empirically — it IS load-bearing).
- Asked whether we can have "full PQ now or wait" — his framing is binary.

### Recommendation for team discussion

1. **Agree on threat model urgency first**. Is real-time quantum impersonation an imminent concern, or years away? This determines whether authentication PQ is urgent or can wait.
2. **Confirm whether (2) standalone is acceptable as an interim**. If yes, we can ship the key exchange work immediately and plan (3) separately. If no (Leemon's current position), we need to start the roster schema work.
3. **Evaluate (4) or (5) as alternatives if (3) is too expensive**. Both trade engineering cost differently:
   - (4) simplifies the architecture but stays classical
   - (5) is fully PQ via a completely different TLS path
4. **Do NOT rely on SunJSSE for PQ authentication**. Oracle has not filed a JEP for it. It's indefinitely blocked.

---

## Open questions

1. What is the performance impact of ML-DSA-65 cert verification at hashgraph throughput? (~3300-byte signatures, slower than RSA)
2. Can BCJSSE use ACCP for its underlying crypto to reduce the 7% latency gap? (pending experiment)
3. Is there a migration path that stages (2) → (3) without two separate roster updates?
4. If we adopt (3), do we retain RSA signing keys for event signatures, or unify to ML-DSA for both?
5. How do we handle key rotation during an in-progress ML-DSA migration — dual signatures? freeze windows? hard cutover?

---

## References

- **JEP 527**: Post-quantum hybrid key exchange in SunJSSE, integrated into JDK 27.
- **JEP 496**: Quantum-resistant module-lattice-based key encapsulation mechanism (ML-KEM), JDK 24.
- **JEP 497**: Quantum-resistant module-lattice-based digital signature algorithm (ML-DSA), JDK 24.
- **RFC 8446**: TLS 1.3.
- **NIST FIPS 203**: ML-KEM (formerly CRYSTALS-Kyber).
- **NIST FIPS 204**: DSA (formerly CRYSTALS-Dilithium).
- **BCJSSE maintainer response on PSK**: [bc-java#1884](https://github.com/bcgit/bc-java/issues/1884) — confirms PSK is not supported in BCJSSE.
- **Cloudflare post-quantum TLS rollout**: production deployment of X25519Kyber768, now moving to X25519MLKEM768.
- **Inside Java blog on JEP 527**: https://inside.java/2026/02/17/tls-post-quantum-hybrid-key-exchange/