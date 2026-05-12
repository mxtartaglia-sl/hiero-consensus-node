# Findings — empirically verified claims

Each finding below has a verification source and a date. If a claim does not appear here, it is not a verified finding — even if it appeared in an older document.

## 1. JSSE provider behaviour

### 1.1 SunJSSE has no PQ TLS support on JDK 25
- **Claim**: SunJSSE silently drops `X25519MLKEM768` named groups and `mldsa*` signature schemes. The handshake either fails or falls back to classical without an error message at default log levels.
- **Verified**: 2026-04-15 via `MtlsDebugMlKemJava` (named-group drop) and `MtlsDebugPqJava` (signature-scheme drop). Direct observation of the `signature_algorithms` extension in the ClientHello.
- **Source class files**: still present in `consensus-tls-debug` source; flag dispatch is currently disabled.

### 1.2 SunJSSE accepts the production gossip key shape
- **Claim**: TLS 1.3 with RSA-3072 CA + EC-384 agrCert + `SHA384withRSA` certs + `SunX509` KMF/TMF + PKCS12 keystore works without changes. This is the current production baseline.
- **Verified**: 2026-04-15 via `MtlsDebugJava`.

### 1.3 The framework verifies the cert signature, not just trust-store membership
- **Claim**: A handshake fails if the agrCert's signature is corrupted, even when the cert is otherwise present in the trust store.
- **Verified**: 2026-04-15 via `--java --corrupt` (one byte flipped in the agrCert signature → `certificate_unknown` failure) and `--rogue-ca` (rogue CA in keystore chain, legit CA in trust store → `Unable to construct a valid chain`).
- **Implication**: the trust model relies on signature verification at handshake time. A quantum adversary that recovers the sigKey can forge agrCerts and impersonate peers.

### 1.4 BCJSSE silently disables ML-KEM when a non-BC provider's `KeyPairGenerator.ML-KEM` is found first
- **Claim**: With BCJSSE's `DefaultJcaJceHelper`, the global JCA chain is walked for ML-KEM lookups. The JDK's own ML-KEM (JDK 25+) or a locally-built ACCP returns first, and BCJSSE then tries to call `initialize` with a BC-specific `MLKEMParameterSpec` — which non-BC providers reject. BCJSSE catches this and silently disables `X25519MLKEM768`. Handshake falls back to classical with no error at default log levels.
- **Verified**: 2026-04-16 — observed silently in early ACCP experiments, definitively confirmed via OpenSSL interop where `openssl s_server -groups X25519MLKEM768` rejected the resulting handshake.

### 1.5 The custom hybrid `JcaJceHelper` resolves the ML-KEM routing problem
- **Claim**: A custom helper that pins `ML-KEM*` lookups to BC and routes everything else through the global chain delivers both real PQ key exchange AND ACCP-accelerated classical operations. About 250 lines.
- **Verified**: 2026-04-16 via OpenSSL interop (100/100 handshakes against `openssl s_server -groups X25519MLKEM768`).
- **Implementation**: see `MtlsDebugHybrid.HybridJcaJceHelper`.

### 1.6 The "ECDH disabled algorithms" workaround is unnecessary
- **Claim**: JDK 21+ disables `ECDH` in `jdk.tls.disabledAlgorithms`. Earlier investigation believed this also blocked ECDSA signature schemes. It does not.
- **Verified**: 2026-04-15 via `MtlsDebugEcdhTest` — leaving the ECDH disable in place but adding `secp384r1` to named groups, ECDSA schemes appear in the ClientHello and the handshake completes.
- **Action**: the patch in `MtlsDebug.java` lines ~149–154 is dead theory and should be removed.

### 1.7 `secp384r1` in named groups is structurally required
- **Claim**: BCJSSE filters TLS 1.3 ECDSA signature schemes based on which named curves are in the configured `namedGroups` list. Without `secp384r1`, `ecdsa_secp384r1_sha384` is silently dropped from the ClientHello even if listed in `signatureSchemes`.
- **Verified**: 2026-04-15 from BCJSSE source inspection (`SignatureSchemeInfo.isNamedGroupOK`) and direct experiment.
- **Implication**: configuration must list `secp384r1` alongside the active key-exchange group, even though `secp384r1` is not used as the kx group itself.

## 2. Cert handling

### 2.1 sigCert is genuinely self-signed in the production code
- **Claim**: `KeysAndCertsGenerator.generate()` calls `CertificateUtils.generateCertificate` with `(dnS, sigKeyPair, dnS, sigKeyPair, ...)` — same DN as subject and issuer, same key pair signs and is the subject. This produces a true RFC 5280 self-signed cert.
- **Verified**: 2026-05-07 via direct code reading (`platform-sdk/consensus-utility/.../KeysAndCertsGenerator.java:114-119`, with the inline comment "both are signed by sigKeyPair, so sigCert is self-signed").
- **Implication**: `gossip_ca_certificate` in the roster is a self-signed cert. PKIX trust-anchor convention says its self-signature is not validated at handshake time.

### 2.2 The `gossip_ca_certificate` field carries full DER, not a hash
- **Claim**: The proto field is `bytes gossip_ca_certificate` and the docstring says "MUST be the DER encoding of the certificate presented." Approximately 1–1.2 KB for the current RSA-3072 self-signed cert.
- **Verified**: 2026-05-07 via direct inspection of `hapi/hedera-protobuf-java-api/src/main/proto/services/state/roster/roster.proto:67` and the corresponding entries in `node_create.proto` and `node_update.proto`.
- **Note**: there is a separate `grpc_certificate_hash` field for gRPC TLS that DOES carry a SHA-384 hash. Different field, different code path — not relevant to gossip.

### 2.3 BCJSSE rejects PKCS#1 v1.5 RSA in TLS 1.3 cert chains by default
- **Claim**: `ProvAlgorithmChecker.checkChain` walks every cert in the chain, including the trust anchor's self-signature, and applies the connection's permitted-signature-scheme list. By default, `SHA384withRSA` is rejected.
- **Verified**: 2026-04-15 via `MtlsDebugMixedPss` first run (failed with `Signature algorithm 'SHA384WITHRSA' not permitted with given parameters`).

### 2.4 Advertising `rsa_pkcs1_sha384` makes BCJSSE accept PKCS#1 v1.5 in cert chains
- **Claim**: Per RFC 8446 §4.2.3, `rsa_pkcs1_*` schemes are explicitly allowed in `signature_algorithms` for cert-chain backward compatibility, while remaining forbidden for handshake `CertificateVerify` signatures. Adding `rsa_pkcs1_sha384` to BCJSSE's `signatureSchemes` lets it accept a PKCS#1 v1.5 self-signed CA in the chain. The handshake `CertificateVerify` signature is still negotiated as PSS or ECDSA.
- **Verified**: 2026-04-15 via `MtlsDebugMixedPss` second run (added `rsa_pkcs1_sha384` to schemes, handshake completed end-to-end).
- **Implication**: the BCJSSE migration does NOT require regenerating sigCerts. The sigCert keeps its existing PKCS#1 v1.5 self-signature; only the agrCert generation algorithm changes from `SHA384withRSA` to `SHA384withRSAandMGF1`. agrCert is regenerated at every node startup, so this is a code-only change with no on-disk migration.

### 2.5 ML-DSA-65 self-signed certs work with the standard JSSE trust path
- **Claim**: A self-signed ML-DSA-65 cert generated via BC's `JcaContentSignerBuilder("ML-DSA-65")` is loadable via the standard JDK `CertificateFactory.getInstance("X.509")` and accepted as a trust anchor in `KeyStore.setCertificateEntry`. DER size is ~5 KB.
- **Verified**: 2026-05-08 via `MtlsDebugDualTrust`. Cert DER size measured at **5494 bytes**. DER round-trip through `CertificateFactory.generateCertificate` returned bytes identical in length to the input.
- **Implication**: the proposed `pq_gossip_ca_certificate` roster field can carry the same DER bytes the cert produces, with no custom serialization code on either end.

### 2.6 The JSSE trust store accepts dual classical + PQ trust anchors
- **Claim**: A single `KeyStore` can hold both an RSA self-signed cert (with `SHA384withRSA` self-signature) and an ML-DSA-65 self-signed cert as trust anchors. PKIX validation against the classical chain still works; the PQ anchor sits dormant when not exercised.
- **Verified**: 2026-05-08 via `MtlsDebugDualTrust`. Trust store iterated to confirm both anchors present, classical handshake completed normally with peer signature `RSASSA-PSS`.
- **Implication**: the Phase 3 mixed-mode trust-store extension is achievable without custom validation code.

## 3. Algorithm support

### 3.1 BC supports ML-KEM-768 (hybrid and pure) in TLS 1.3 via BCJSSE
- **Claim**: Both `X25519MLKEM768` (hybrid) and `MLKEM768` (pure) named groups complete TLS 1.3 handshakes via BCJSSE.
- **Verified**: 2026-04-15 (hybrid) via `MtlsDebugMlKem` and OpenSSL interop. 2026-05-08 (pure) via re-measurement on the unified `MtlsDebugHybrid` harness with the new `--pure` flag.

### 3.2 BC supports ML-DSA-65 for TLS authentication
- **Claim**: ML-DSA-65 keypairs and self-signed certs generated via BC, used as the cert chain for both server and client, complete a TLS 1.3 mTLS handshake. ACCP cross-provider compatibility for ML-DSA private keys (PKCS#8 round-trip) confirmed.
- **Verified**: 2026-04-16 via `MtlsDebugHybrid --mldsa`.

### 3.3 ACCP cannot accelerate BCJSSE when BCJSSE is pinned to BC
- **Claim**: `new BouncyCastleJsseProvider(bcProv)` constructs a `ProviderJcaJceHelper(bcProv)` that goes directly to BC for crypto lookups, bypassing the global provider chain. ACCP at JCA position 1 is never invoked.
- **Verified**: 2026-04-16 — measurements show identical latency for BCJSSE-pinned-to-BC with and without ACCP registered.

## 4. Production code path

### 4.1 The state signing key is the same key as the gossip trust anchor
- **Claim**: `PlatformSigner` is constructed from `keysAndCerts.sigKeyPair()`. `DefaultStateSigner` uses `PlatformSigner.sign()` to sign state hashes. The same `sigKey` also signs gossip events and is the private key paired with `gossip_ca_certificate` in the roster.
- **Verified**: 2026-05-07 via direct code reading (`PlatformSigner.java:22-30`, `DefaultStateSigner.java:50`, `KeysAndCertsGenerator.java:108-117`).
- **Implication**: state-signing PQ migration cannot be done independently of the gossip authentication migration — same key. Both belong to the future event/state-signing PQ track using whichever scheme the team selects.

### 4.2 `SigningSchema` enum has only RSA and Ed25519 today
- **Claim**: No PQ entries in the `SigningSchema` enum. Adding ML-DSA (or any PQ scheme) to event/state signing requires an enum addition plus implementation.
- **Verified**: 2026-05-07 via direct code reading (`PlatformSigner.java:24-29`).

## 5. IETF / standards status (verified 2026-05-08)

### 5.1 Hybrid ML-KEM kx: `draft-ietf-tls-ecdhe-mlkem-04`
- **Status**: Standards Track (Proposed Standard), submitted to IESG, **in RFC Editor Queue**.
- **Code points**: `X25519MLKEM768 = 0x11EC`, `SecP256r1MLKEM768 = 0x11EB`, `SecP384r1MLKEM1024 = 0x11ED`.
- **Wire format**: stable for practical purposes; only editorial changes expected before RFC publication.

### 5.2 Pure ML-KEM kx: `draft-ietf-tls-mlkem-07`
- **Status**: Informational, WG-adopted, currently in WGLC (Working Group Last Call) with "Revised I-D Needed".
- **Code points**: `mlkem512 = 0x0200`, `mlkem768 = 0x0201`, `mlkem1024 = 0x0202`.
- **Wire format**: subject to one more revision pass; minor changes possible.

### 5.3 ML-DSA in TLS authentication: `draft-ietf-tls-mldsa-03`
- **Status**: Informational, submitted to IESG, awaiting AD action.
- **Code points**: `mldsa44 = 0x0904`, `mldsa65 = 0x0905`, `mldsa87 = 0x0906`.
- **Wire format**: stable across the three WG revisions; significant changes unlikely before publication.

### 5.4 Falcon / FN-DSA in TLS
- **Status**: no IETF draft, no IANA code points assigned. Not deployable today via any TLS stack.
- **Verified**: IANA TLS signature scheme registry inspection (2026-04-16).

## 6. Performance

Performance numbers are in [`performance.md`](./performance.md). Methodology, raw results, and analysis are documented there. Each table includes the date measured and the harness configuration.

## 7. What we deliberately have NOT verified

These are open items that the canonical proposal does not assume:

- **Linux x86_64 numbers.** All `performance.md` measurements are macOS arm64 dev hardware. Production-target numbers should be re-captured on Linux before launch.
- **OpenSSL interop with ML-DSA.** `MtlsDebugHybrid --mldsa` proves BC↔BC ML-DSA works; an OpenSSL peer using ML-DSA has not been tested. Worth doing before deploying against any non-BC peer.
- **Long-running stability.** Millions of handshakes over hours to flush native-library leaks, JIT regressions, GC pressure surprises. Not done.
- **Per-operation microbenchmarks.** No isolated benchmarks of ML-DSA-65 sign/verify, RSA-PSS verify, or AES-GCM throughput in BC vs ACCP. Past inferred numbers from queue dynamics are not included here.
- **PKCS12 vs BKS keystore under BCJSSE.** The prototype uses BKS; PKCS12 may also work but has not been verified against the production cert shape.