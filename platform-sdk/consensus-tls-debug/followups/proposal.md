
# Proposal — Post-Quantum TLS for Consensus Gossip

| | |
|---|---|
| **Status** | Open for review |
| **Date** | 2026-05-08 |
| **Audience** | Consensus team |
| **Companion docs** | [`findings.md`](./findings.md), [`performance.md`](./performance.md), [`experiments.md`](./experiments.md) |

This document proposes a phased migration of consensus-node gossip mTLS to post-quantum cryptography. It states what we want to do and why, the system surfaces affected, the rollout plan, and the decisions the team must close before engineering begins.

Every empirical claim in this document is verified — see [`findings.md`](./findings.md) for the source experiment for each, and [`performance.md`](./performance.md) for the measurements.

---

## 1. What we propose

Move gossip mTLS from classical cryptography (RSA-3072, EC-384, x25519) to post-quantum cryptography. Specifically:

1. **Key exchange**: hybrid `X25519MLKEM768`. Standards Track at IETF, in the RFC Editor Queue. Provides defense-in-depth — classical security if ML-KEM-768 is later weakened, post-quantum security if x25519 is broken.
2. **Authentication**: ML-DSA-65. The IETF draft is at revision 03 (Informational), submitted to IESG. Code points stable.
3. **TLS provider**: BCJSSE with a custom hybrid `JcaJceHelper` that pins ML-KEM operations to BouncyCastle while routing everything else through the global JCA chain (where ACCP intercepts classical operations).
4. **Acceleration**: ACCP at JCA position 1, locally built with ML-KEM support enabled.

Symmetric encryption (AES-256-GCM) is already considered post-quantum-safe in the configuration the network uses and is unchanged.

---

## 2. Why now

The current gossip stack is vulnerable to real-time TLS-level forgery once quantum capability arrives. Migrating ahead of any mandated timeline is operationally cheaper than reacting under pressure. Recent IETF progress puts this within reach today — hybrid ML-KEM is in the RFC Editor Queue, ML-DSA-in-TLS is at the IESG, and the BouncyCastle stack supports both. The platform-side work has been prototyped and validated end-to-end.

---

## 3. What changes

### 3.1 Platform TLS

- JSSE provider: `SunJSSE` → `BCJSSE`.
- KeyManagerFactory / TrustManagerFactory: `SunX509` → `PKIX`. PKIX requires explicit `PKIXBuilderParameters.setRevocationEnabled(false)` because the network does not operate CRL/OCSP infrastructure.
- Keystore type: assumed `PKCS12` pending verification under BCJSSE; the prototype uses `BKS` but this is not proven to be required (open decision).
- Named groups: `["X25519MLKEM768", "secp384r1"]`. The `secp384r1` entry is structurally required by BCJSSE for ECDSA signature scheme activations and must stay even though x25519 / ML-KEM is the active key-exchange group.
- Signature schemes (during transition): `mldsa65`, classical schemes (`ecdsa_secp384r1_sha384`, `ed25519`, `rsa_pss_*`), and `rsa_pkcs1_sha384` for cert-chain compatibility per RFC 8446 §4.2.3.
- Custom hybrid `JcaJceHelper` — ~250 lines, prototype lives in `MtlsDebugHybrid.HybridJcaJceHelper`. Required if ACCP is registered.

### 3.2 Certificates

A finding from `findings.md` §2.4 reduces this surface significantly:

- **The self-signed sigCert (RSA-3072) stays unchanged.** No DER change. No fleet keystore migration.
- **The agrCert signing algorithm changes** from `SHA384withRSA` (PKCS#1 v1.5) to `SHA384withRSAandMGF1` (RSA-PSS). agrCert is regenerated at every node startup, so this is a code change in the agrCert generation path with no on-disk artifact migration.
- **A second cert-generation path** produces ML-DSA-65 keypairs and self-signed certs for the new chain.

### 3.3 HAPI / proto

A new field is added:

```protobuf
bytes pq_gossip_ca_certificate = N;  // DER-encoded ML-DSA-65 self-signed cert, ~5 KB
```

Mirrored in:

- `RosterEntry` (state)
- `Node` (state)
- `NodeCreateTransactionBody` (DAB)
- `NodeUpdateTransactionBody` (DAB, as `BytesValue` for optional update)

The field carries DER bytes of an ML-DSA-65 self-signed certificate, in the same shape as the existing `gossip_ca_certificate`. Round-tripping through the standard JDK `CertificateFactory.getInstance("X.509")` works without custom serialization code (verified — see `findings.md` §2.5). Measured DER size: 5494 bytes.

### 3.4 State / migration

- Roster service schema version bumped.
- Existing roster entries get the field as null/empty on migration; nodes populate it via `nodeUpdate` during Phase 2.
- `RosterValidator` adds a rule: well-formed X.509 certificate parseable through `CertificateFactory`, size within budget.
- DAB handlers (`NodeCreateHandler`, `NodeUpdateHandler`) add validation and field copy.
- Fee schedule audit: ~5 KB added to `nodeCreate` / `nodeUpdate` payload.

### 3.5 Trust path

Trust-store generation extends to consume both roster fields:

- `gossip_ca_certificate` (existing classical RSA cert)
- `pq_gossip_ca_certificate` (new ML-DSA cert)

Both contribute trust anchors to the JSSE trust store via `KeyStore.setCertificateEntry`. The TLS handshake configuration accepts both classical and ML-DSA signature schemes during the transition window. After classical retirement, only ML-DSA remains. PKIX trust semantics are unchanged — the migration adds algorithms; it does not change the trust mechanism. Verified end-to-end via the dual-trust experiment (`findings.md` §2.6).

### 3.6 Tooling

- `pcli generate-keys` (or equivalent) gains an ML-DSA-65 keypair generation path.
- Operator tools (e.g., `yahcli`) gain a flag to attach `pq_gossip_ca_certificate` to a `nodeUpdate`.
- Genesis-network specifications can optionally seed the field for new networks.

### 3.7 Ecosystem (cross-team)

Every consumer of `RosterEntry` regenerates protobuf bindings. Wire compatibility is preserved (protobuf field addition is forward and backward compatible) — old consumers ignore the field, new consumers read it. This holds during Phases 2 and 3. Once Phase 4 makes the field load-bearing for trust validation, all readers MUST understand it.

Affected:

- Mirror Node — roster parser, explorer / API surfaces.
- Block Node — roster parser.
- SDKs (Java, Go, JavaScript, .NET, Rust, Python, Swift) — `Key` model addition, roster decoding.

These releases SHOULD precede the consensus-side flip that makes the field load-bearing.

---

## 4. Migration plan

Five phases, each independently deployable and rollback-able.

### Phase 1 — New TLS stack, classical authentication

Platform-only. No HAPI changes. No roster changes.

- Switch JSSE provider to BCJSSE.
- Add ACCP, register at JCA position 1.
- Wire the custom hybrid `JcaJceHelper`.
- Switch KMF / TMF to `PKIX` with revocation explicitly disabled.
- Switch agrCert signing to `SHA384withRSAandMGF1`.
- TLS configuration: classical signature schemes plus `rsa_pkcs1_sha384` for cert-chain compatibility, plus `X25519MLKEM768` in named groups (enables hybrid PQ key exchange).

The sigCert in the roster is unchanged. No fleet keystore migration is required if PKCS12 is verified compatible with BCJSSE (open decision below).

### Phase 2 — PQ-capable transport (HAPI change)

- Add `pq_gossip_ca_certificate` field to `RosterEntry`, `Node`, and DAB transaction bodies.
- Bump roster service schema version; migration initializes the field as empty.
- DAB handlers validate and copy the field.
- ML-DSA-65 keypair generation tooling becomes available.
- Nodes optionally generate their PQ key and populate the field via `nodeUpdate`.
- TLS authentication remains classical at this phase.

This phase requires HAPI coordination across Mirror Node, Block Node, and SDKs.

### Phase 3 — Dual-authentication window

- TLS configuration adds `mldsa65` to `signatureSchemes`.
- Trust-store generation consumes both `gossip_ca_certificate` and `pq_gossip_ca_certificate`.
- Nodes that have populated their PQ key participate in PQ-authenticated handshakes; nodes that have not fall back to classical.
- The network operates in mixed mode until every node has populated `pq_gossip_ca_certificate`.

A close criterion ("all nodes populated for ≥30 days with no PQ-attributable failures") gates the move to Phase 4. Operations team owns the criterion.

### Phase 4 — PQ-required transport

- Classical signature schemes removed from the TLS configuration.
- Classical agrCert generation path retired (or kept dormant for legacy DR).
- `pq_gossip_ca_certificate` becomes required at the validator level.
- Hybrid key exchange retained — x25519 component still provides classical security against ML-KEM cryptanalysis.

### Phase 5 — Event/state signing migration

Out of scope. Event signing and state signing share the same `sigKey` and migrate together on a separate track using whichever PQ scheme the team selects (likely Falcon or another PQ signature whose Java implementation is not yet available). This proposal does not commit either way. See [`findings.md`](./findings.md) §4.1 for the code-level confirmation that state signing rides on the gossip sigKey.

---

## 5. Performance summary

Full numbers in [`performance.md`](./performance.md). Headline:

| Configuration | Mean handshake (with ACCP, macOS arm64) |
|---|---|
| Classical x25519, classical auth (today's baseline shape) | 1.476 ms |
| **Pure ML-KEM kx + ML-DSA auth (full PQ)** | **1.566 ms** |
| Hybrid `X25519MLKEM768` + ML-DSA auth (full PQ, recommended) | 1.851 ms |

Going fully post-quantum costs +375 µs over the fastest classical configuration when paired with hybrid kx (the deployment-track choice). At Hedera handshake rates, this is below the noise floor of node-level CPU.

When BCJSSE is properly pinned to BC for classical primitives (the production fallback intent when ACCP isn't deployed), no-ACCP latency lands around 2.1–2.5 ms across all six BCJSSE configurations — Matrix A and Matrix B alike. ML-DSA-auth handshakes run ~150–200 µs faster than classical-auth handshakes in the no-ACCP case, a small but consistent benefit. So a deployment that cannot ship ACCP isn't paying a penalty for moving to ML-DSA.

Linux x86_64 numbers are pending. Relative ordering is expected to hold.

---

## 6. Risks

| Risk | Mitigation |
|---|---|
| BCJSSE silently disables ML-KEM if a non-BC provider's `KeyPairGenerator.ML-KEM` is found first | The custom hybrid `JcaJceHelper` pins ML-KEM lookups to BC explicitly. Validated via OpenSSL interop. Provider ordering must remain deterministic in startup; any change to ordering MUST be re-validated. |
| ACCP "zero-services" failure mode (provider registers but native lib mismatches host arch → all `getInstance` calls return null) | Deployment ships per-arch ACCP jars (`linux-x86_64`, `linux-aarch_64`, `osx-aarch_64`, `osx-x86_64`). Auto-detection at startup. Documented operational hint. |
| `mldsa65` references an IETF draft (not RFC) | Draft is at -03, Informational, submitted to IESG. Code points are stable. Wire-format change unlikely before publication but possible — assign standards-tracking ownership to pick up any AD-discuss revision. |
| HAPI rollout drift: Phase 3 closes before some consumer has read the field | Mixed-mode soak window with explicit close criterion. Field stays optional during Phases 2–3. Phase 4 only proceeds after operations team confirms close criterion. |
| Cert refresh is irreversible per node — once a node's agrCert generation moves to PSS, classical-auth peers using PKCS#1 v1.5 in the chain require `rsa_pkcs1_sha384` advertised | The `rsa_pkcs1_sha384` cert-compat scheme is part of the Phase 1 TLS configuration from the start, so this is handled. |

---

## 7. Open decisions

The team must close the following before Phase 1 begins:

| # | Decision | Owner | Notes |
|---|---|---|---|
| 1 | Endorse this proposal as the path forward | Consensus team | Acceptance of direction; engineering sizing follows. |
| 2 | ML-DSA parameter set — 44 / 65 / 87 | Cryptography team or technical leadership | Experiments used 65; lower trades security for size, higher trades cost for margin. |
| 3 | Keystore format under BCJSSE | Platform team | Verify whether PKCS12 works under BCJSSE before sizing Phase 1. If not, BKS migration becomes in scope. |
| 4 | Standards-tracking ownership for `draft-ietf-tls-mldsa` | Engineering management | Ongoing operational role until RFC publishes. |
| 5 | Migration cadence: per-phase soak windows, mixed-mode duration | Operations team | Affects rollback complexity and time to retire classical. |

---

## 8. Validation status

What has been verified empirically (see [`findings.md`](./findings.md) for source experiments):

- Hybrid `X25519MLKEM768` works end-to-end via BCJSSE + hybrid helper, including OpenSSL interop.
- Pure `MLKEM768` works end-to-end (less production-relevant; informational).
- ML-DSA-65 self-signed certs generate, serialize, deserialize, and load as trust anchors via the standard JSSE APIs. DER size 5494 bytes.
- Mixed-PSS chain (PKCS#1 v1.5 sigCert + PSS agrCert) accepted by BCJSSE when `rsa_pkcs1_sha384` is in `signatureSchemes`. **Eliminates fleet sigCert refresh from migration scope.**
- Dual trust anchors (classical RSA + ML-DSA) coexist in a single JSSE trust store without disrupting classical handshakes. Validates the Phase 3 trust-store extension.
- Performance matrix across 12 configurations × 3 trials. ACCP gives ~3× on classical-auth, ~10–13% on ML-DSA-auth handshakes.

What has NOT been verified yet:

- Linux x86_64 numbers (production target).
- OpenSSL interop with ML-DSA on the wire (BC↔BC ML-DSA confirmed; cross-stack not).
- Long-running stability (millions of handshakes, hours of uptime).
- Per-operation microbenchmarks for ML-DSA sign/verify in isolation.
- PKCS12 keystore vs BKS under BCJSSE with the production cert shape.

These are listed under "What we deliberately have NOT verified" in `findings.md` §7 and tracked as work to do before launch.

---

## 9. What this proposal does NOT propose

- Event signing migration. Same key as gossip but on a separate track.
- State signing migration. Same key as gossip; same separate track as event signing.
- JDK upgrade. The proposal works on the current JDK.
- BC-FIPS distribution. Standard BCJSSE is sufficient. FIPS-certified variants are a separate decision if compliance becomes a requirement.
- Migration to a different PQ signature scheme later (Falcon, SLH-DSA, etc.). The architecture supports a second PQ key field if needed; this proposal does not commit either way.