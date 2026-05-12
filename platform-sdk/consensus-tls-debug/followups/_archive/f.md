# RFC-001: Post-Quantum TLS Transition for Consensus Gossip

| | |
|---|---|
| **Status** | Proposal — open for review |
| **Audience** | Consensus team |
| **Date** | 2026-05-07 |
| **Replaces** | none |
| **Replaced by** | none |
| **Tags** | tls, post-quantum, gossip, hapi, roster |

---

## Abstract

This RFC proposes a phased transition of consensus-node gossip mTLS from classical cryptography (RSA-3072 / EC-384 / x25519) to post-quantum cryptography (hybrid `X25519MLKEM768` for key exchange and ML-DSA for authentication). The transition replaces the JSSE provider stack, introduces a second public-key field in the roster for PQ authentication, and is structured so that each phase can be deployed and validated independently. Event signing and state signing are explicitly out of scope; they migrate on a separate track.

---

## 1. Introduction
This document is a proposal. It establishes the technical direction, the rollout sequence, and the system surfaces affected by the migration. It does not commit the team to engineering effort; that decision follows team review.

### 1.1 Motivation

Gossip mTLS today relies on RSA-3072 and EC-384 for authentication and on x25519 for key exchange. None of these are quantum-safe at the algorithmic level. This proposal moves gossip transport onto post-quantum primitives ahead of any mandated timeline so that quantum-capable adversaries cannot impersonate consensus peers on a live network. Symmetric encryption (AES-256-GCM) is already considered post-quantum-safe in the configuration the network uses and is unchanged by this work.

### 1.2 What this RFC covers

In scope:

- Gossip TLS authentication via ML-DSA
- Gossip TLS key exchange via hybrid `X25519MLKEM768`
- The JSSE provider replacement required to support either
- The roster schema change required to anchor PQ authentication
- The phased rollout sequence and operational concerns

Out of scope:

- Event signature migration
- State signature migration
- Application-level transactions
- Consensus protocol changes
- JDK upgrade decisions

### 1.3 What this RFC asks of the team

Endorsement of the proposed direction:

- Accept ACCP complexity as a pay of the performance gains
- BCJSSE as the TLS provider going forward (Section 3)
- Adding `pq_gossip_public_key` as a new field in `RosterEntry` (Section 4.4)
- The five-phase rollout sequence (Section 5)
- The ML-DSA parameter set (Section 3.4 — currently open)

---

## 2. Terminology and background

### 2.1 TLS handshake phases

A TLS 1.3 handshake has three independent cryptographic phases:

- **Key exchange**: derives a shared ephemeral secret. Today: x25519. Proposed: hybrid `X25519MLKEM768` (an x25519 share plus an ML-KEM-768 ciphertext, combined into the session secret).
- **Authentication**: each side proves identity with a certificate and a `CertificateVerify` signature over the handshake transcript. Today: RSA-PSS or ECDSA. Proposed: ML-DSA (with classical retained during transition).
- **Symmetric encryption**: encrypts session traffic. Already post-quantum-safe in the current configuration: AES-256-GCM is reduced to ~128-bit security under Grover's algorithm, which is still considered secure.

Only the first two phases require cryptographic change.

### 2.2 Current gossip identity model

Each consensus node holds two related materials:

- **sigKey / sigCert**: long-lived signing key (RSA-3072 today). The self-signed cert is published in the roster as `gossip_ca_certificate` (full DER bytes). The same key signs gossip events and signed-state hashes.
- **agrCert**: ephemeral agreement certificate generated in memory at startup, signed by the sigKey, used to identify the node during TLS handshakes. EC-384 today.

The roster's `gossip_ca_certificate` is loaded into the JSSE trust store on startup and serves as the trust anchor. The trust path validated on each handshake is `agrCert → sigCert`, with `sigCert` matched against the trust anchor in the roster. The roster has therefore always been the effective transport trust root; the changes proposed here extend that role with a second key.

### 2.3 Acronyms used in this document

- **BCJSSE**: BouncyCastle's JSSE provider implementation.
- **ACCP**: Amazon Corretto Crypto Provider — a JCA provider backed by AWS-LC native code, providing accelerated classical primitives and (in some builds) ML-DSA.
- **ML-KEM**: Module-Lattice Key Encapsulation Mechanism (NIST FIPS 203).
- **ML-DSA**: Module-Lattice Digital Signature Algorithm (NIST FIPS 204).
- **PKIX**: Public-Key Infrastructure for X.509 certificates (RFC 5280).
- **PSS**: Probabilistic Signature Scheme — the RSA padding mode required for handshake signatures in TLS 1.3.
- **PKCS#1 v1.5**: legacy RSA padding;
- **JCA / JSSE**: Java Cryptography Architecture / Java Secure Socket Extension — the provider frameworks in the JDK.
- **DAB**: Dynamic Address Book — the transaction family (`nodeCreate`, `nodeUpdate`) that updates roster entries.

---

## 3. Proposed approach

### 3.1 TLS provider stack

| Component | Role | Status |
|---|---|---|
| BCJSSE | TLS implementation | **Required** for both PQ kx and PQ auth |
| BouncyCastle JCA provider | ML-KEM and ML-DSA primitives | **Required** |
| ACCP | Classical crypto acceleration; ML-DSA in some builds | **Recommended** (not required for correctness) |
| Custom hybrid `JcaJceHelper` | Routes ML-KEM to BC, classical operations through the chain to ACCP | **Required** if ACCP is included |

The current default JSSE provider does not support post-quantum primitives in the TLS handshake: it silently drops both `X25519MLKEM768` named groups and `mldsa*` signature schemes from the ClientHello. JEP 527 in JDK 27 adds PQ key exchange to the default provider, but no JEP exists for PQ authentication, and realistic timelines for that work measure in years. BCJSSE is therefore the only viable path to full PQ TLS in the near term.

### 3.2 Provider ordering

Provider order in the JCA chain is operationally significant. BCJSSE silently disables `X25519MLKEM768` if any non-BC provider in the global chain registers `KeyPairGenerator.ML-KEM` ahead of BC. This includes the JDK's own ML-KEM provider on JDK 25+ and locally-built ACCP variants.

The custom `JcaJceHelper` resolves this routing problem:

- ML-KEM lookups are pinned explicitly to BC.
- Classical primitives (RSA, ECDH, AES-GCM, hashes) and ML-DSA route through the global chain so ACCP intercepts them.

This combination is the only configuration that delivers both real PQ key exchange and ACCP-accelerated classical operations.

### 3.3 Cryptographic primitives

| Primitive | Role | Algorithm |
|---|---|---|
| Key exchange | TLS handshake key agreement | `X25519MLKEM768` (hybrid) |
| Authentication signature scheme | `CertificateVerify` and cert chain | `mldsa65` (PQ); classical schemes retained during transition; `rsa_pkcs1_sha384` advertised for cert-chain compatibility (Section 4.2) |
| Symmetric cipher | session encryption | `TLS_AES_256_GCM_SHA384` (unchanged) |
| sigKey / sigCert | roster trust anchor + event/state signing | RSA-3072 retained |
| agrKey / agrCert (legacy chain) | TLS handshake identity | EC-384 retained; agrCert signed `SHA384withRSAandMGF1` |
| pqAgrKey / pqAgrCert (PQ chain) | TLS handshake identity | ML-DSA-65 keypair, ML-DSA-65 self-signed |

### 3.4 ML-DSA parameter set

Experiments to date used ML-DSA-65 because it provides a balanced trade-off between security level (NIST category 3), signature size (~3.3 KB), and verification cost for transport authentication. ML-DSA-44 trades smaller artifacts for a lower security level (category 2). ML-DSA-87 increases computational and bandwidth cost (~4.6 KB signatures) without clear operational benefit at this layer.

Final selection is **deferred**, listed as Open Decision 2 in Section 8.

---

## 4. System changes

### 4.1 TLS factory and configuration

`TlsFactory` and the surrounding TLS-construction code are parameterized so the JSSE provider, KMF/TMF type, keystore type, named groups, and signature schemes are no longer hardcoded. The runtime configuration is:

- JSSE provider: `BCJSSE` (was `SunJSSE`).
- Switch KEY_MANAGER_FACTORY/TRUST_MANAGER_FACTORY type: `PKIX` (was `SunX509`). PKIX requires explicit revocation-checking configuration via `PKIXBuilderParameters.setRevocationEnabled(false)` because the network does not operate CRL/OCSP infrastructure.
- Keystore type: `PKCS12` is the working assumption pending verification under BCJSSE; the prototype uses `BKS` but this has not been proven required (Open Decision 3).
- Named groups: `["X25519MLKEM768", "secp384r1"]`. BCJSSE couples some signature-scheme activations to named-group membership, so `secp384r1` is structurally required even though it is not used as the active key-exchange group.
- Signature schemes during transition: `["mldsa65", "ecdsa_secp384r1_sha384", "ecdsa_secp256r1_sha256", "ed25519", "rsa_pss_rsae_sha384", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha384"]`.

### 4.2 Certificate generation

BCJSSE applies the connection's permitted signature-scheme list to every certificate in the chain, including the trust anchor's self-signature. By default this rejects `SHA384withRSA` (PKCS#1 v1.5) self-signed CAs.

RFC 8446 §4.2.3 explicitly allows `rsa_pkcs1_*` schemes in the connection's signature-scheme list for cert-chain backward compatibility, while forbidding them for handshake `CertificateVerify` signatures. Advertising `rsa_pkcs1_sha384` in the connection's `signatureSchemes` therefore lets BCJSSE accept a PKCS#1 v1.5 self-signed CA in the chain without weakening handshake security — the protocol mandates PSS or ECDSA / Ed25519 / ML-DSA for the actual handshake signature regardless.

This finding has been verified end-to-end against BCJSSE TLS 1.3 with the production gossip key types (RSA-3072 sigKey, EC-384 agrKey).

The implications for the migration are:

- **The self-signed sigCert stays on PKCS#1 v1.5.** No DER change. No roster update for the cert-format migration.
- **The agrCert signing algorithm changes from `SHA384withRSA` to `SHA384withRSAandMGF1`.** This is a code-only change in the agrCert generation path. agrCert is regenerated at every node startup, so there is no on-disk artifact to migrate.
- **A second cert generation path produces ML-DSA keypairs and self-signed certs** for the new chain.

### 4.3 Trust path

Trust-store generation extends to consume two roster fields:

- `gossip_ca_certificate` (existing): DER bytes of the classical RSA self-signed cert.
- `pq_gossip_key` (new): DER bytes of the ML-DSA-65 self-signed cert. Same shape as `gossip_ca_certificate`, just a different signature algorithm.

Both contribute trust anchors to the JSSE trust store. The TLS handshake configuration accepts both classical and ML-DSA signature schemes during the transition window. After classical retirement (Phase 4), only ML-DSA remains.

Trust derivation remains PKIX-based throughout. The migration adds algorithms; it does not change the trust mechanism.

### 4.4 Roster schema

A new field is added to `RosterEntry` and to its mirrors in DAB transactions and the `Node` state structure:

```
RosterEntry {
    ...existing fields...
    bytes pq_gossip_ca_certificate = N;  // DER-encoded ML-DSA self-signed cert, ~5 KB
}
```

Mirrored in:

- `Node` (state proto)
- `NodeCreateTransactionBody` (DAB transaction)
- `NodeUpdateTransactionBody` (DAB transaction; `BytesValue` wrapper for optional update)

Validation rules:

- The field is **optional** during Phases 2 and 3.
- The field is **required** for nodes participating in Phase 4 PQ-only authentication.

A full self-signed cert is approximately 5 KB at the ML-DSA-65 parameter set: ~200–400 B of TBS metadata, ~2 KB of `SubjectPublicKeyInfo` (algorithm OID + 1952-byte raw key), and ~3.3 KB for the ML-DSA-65 self-signature blob.

### 4.5 DAB transaction handlers

`NodeCreateHandler` and `NodeUpdateHandler` add validation and field-copy logic for `pq_gossip_ca_certificate`. Fee calculation is reviewed because adding ~5 KB to the transaction payload can shift byte-cost components.

### 4.6 State migration

The roster service schema version is bumped. Existing roster entries get the new field as null/empty on migration. Nodes populate the field through `nodeUpdate` transactions during Phase 2.

### 4.7 Tooling

- Key-generation tooling (`pcli generate-keys` or equivalent) gains an ML-DSA-65 keypair generation path alongside the existing RSA / EC paths.
- Operator tools (e.g., `yahcli`) gain a flag to attach `pq_gossip_ca_certificate` to a `nodeUpdate` transaction.
- Genesis-network specifications can optionally seed the field for new networks.

### 4.8 Ecosystem (cross-team)

Every consumer of `RosterEntry` regenerates protobuf bindings. Protobuf field addition is forward and backward compatible on the wire — old consumers ignore the field, new consumers read it. The compatibility window covers Phases 2 and 3, but cannot extend forever: once Phase 4 makes the field load-bearing for trust validation, all readers MUST understand it.

Affected consumers:

- Mirror Node — roster parser; explorer / API surfaces that expose roster.
- Block Node — roster parser.
- SDKs (Java, Go, JavaScript, .NET, Rust, Python, Swift) — `Key` model addition, roster decoding.

These releases SHOULD precede the consensus-side flip that makes the field load-bearing.

---

## 5. Migration plan

The migration is structured in five phases, each independently deployable and rollback-able.

### 5.1 Phase 1 — Classical baseline on the new stack

- Switch the JSSE provider to BCJSSE.
- Add ACCP to the runtime; register at JCA position 1.
- Wire the custom hybrid `JcaJceHelper`.
- Switch KEY_MANAGER_FACTORY/TRUST_MANAGER_FACTORY to `PKIX`, with revocation checking explicitly disabled.
- Switch agrCert signing to `SHA384withRSAandMGF1` (the only algorithm change required for the legacy chain).
- TLS configuration adds `X25519MLKEM768` to named groups, enabling PQ key exchange , plus `rsa_pkcs1_sha384` for cert-chain compatibility.
- TLS authentication remains classical.

The sigCert in the roster is **unchanged**. No keystore migration is required if PKCS12 is verified compatible with BCJSSE (Open Decision 3).

Phase 1 is platform-only. No HAPI changes. No roster changes. No coordinated network operation required beyond a synchronized rolling restart.

### 5.2 Phase 2 — PQ-capable transport, classical authentication

- Add `pq_gossip_ca_certificate` field to `RosterEntry`, `Node`, and DAB transaction bodies (HAPI proto change).
- Bump the schema version on the roster service; add migration logic that initializes the field as empty for existing entries.
- DAB handlers validate and copy the field.
- ML-DSA keypair generation tooling becomes available.
- Nodes optionally generate their PQ key and populate the field via `nodeUpdate`.

This phase requires HAPI coordination (Mirror Node, Block Node, every SDK).

### 5.3 Phase 3 — Dual-authentication window

- TLS configuration adds `mldsa65` to `signatureSchemes`.
- Trust-store generation consumes both `gossip_ca_certificate` and `pq_gossip_ca_certificate`.
- Nodes that have populated their PQ key participate in PQ-authenticated handshakes; nodes that have not fall back to classical authentication.
- The network operates in mixed mode until every node has populated `pq_gossip_ca_certificate`.

A clear close criteria (e.g., "all nodes have populated their PQ key for ≥30 days with no PQ-attributable handshake failures") gates the move to Phase 4.

### 5.4 Phase 4 — PQ-required transport

- Classical signature schemes are removed from the TLS configuration.
- The classical agrCert generation path is retired (or kept dormant for legacy disaster-recovery scenarios).
- `pq_gossip_ca_certificate` becomes required at the validator level; rosters with empty fields are rejected.
- Hybrid key exchange is retained — the x25519 component continues to provide classical security alongside ML-KEM.

### 5.5 Phase 5 — Out of scope

Event-signature and state-signature migration are on a separate track. See Section 7 for how this proposal interacts with that future work.

---

## 6. Operational considerations

### 6.1 Native dependencies

ACCP loads a native library at startup. Deployment requires:

- Platform-specific ACCP artifacts in deployment bundles (`linux-x86_64`, `linux-aarch_64`, `osx-aarch_64`, `osx-x86_64`).
- The JVM flag `--enable-native-access=ALL-UNNAMED` (or the module-targeted equivalent on JPMS-strict builds).
- Auto-detection or explicit configuration when host and container architectures differ. A mismatched native library causes ACCP to enter a "zero-services" state in which the Java provider object is registered but exposes no algorithms — a silent failure mode that operators must be aware of.

### 6.2 Provider ordering

Provider registration order in the runtime startup sequence MUST be deterministic. The recommended order is:

1. ACCP at position 1.
2. BC at position 2.
3. BCJSSE last, constructed with a `JcaTlsCryptoProvider` that returns the hybrid helper.

Any change to this ordering MUST be re-validated against the regression criterion: BCJSSE silently falling back to classical key exchange instead of erroring loudly.

### 6.3 Standards-tracking responsibility

`mldsa65` in TLS references an IETF draft, not a published RFC. Code points are stable, but salt construction, hash binding, and similar wire details can change across draft revisions until the RFC publishes (anticipated 2027). Someone on the team owns:

- Tracking IETF draft revisions for `draft-ietf-tls-mldsa`.
- Coordinating BC and BCJSSE upgrades when the wire format shifts.
- Communicating timing of any required network-wide upgrade to operators.

This is an ongoing operational role, not a one-time task. Listed as Open Decision 4.

### 6.4 Mixed-mode soak window

The Phase 3 dual-authentication window MUST remain open until every node has populated `pq_gossip_ca_certificate` and rebuilt its trust store. Closing it prematurely fragments the network — nodes that have not populated their PQ key would be unable to authenticate. The operations team defines the close criterion explicitly before Phase 4 begins.

### 6.5 Rollback semantics

Each phase is rollback-able:

- **Phase 1 rollback**: revert TLS configuration to SunJSSE / classical paths. The sigCert is untouched, so no data migration is required. The agrCert PSS change is reverted as a code rollback.
- **Phase 2 rollback**: HAPI consumers roll back to a pre-field protobuf version. The field is still optional, so the network operates without it. Existing population of the field is preserved in state for forward progress.
- **Phase 3 rollback**: remove `mldsa65` from `signatureSchemes`; PQ-populated nodes continue to authenticate classically.
- **Phase 4 rollback**: re-add classical schemes to the TLS configuration; retain `pq_gossip_ca_certificate` so the network can resume Phase 4 without re-running Phases 2 and 3.

### 6.6 Node key provisioning

The migration introduces a second transport private key on every node.

Operators must provision, store, back up, and restore:

- Existing sigKey material
- New ML-DSA private key material used for PQ TLS authentication

The private PQ key never leaves the node filesystem. Only the corresponding public key (`pq_gossip_ca_certificate`) is published through roster state.

Provisioning and disaster-recovery procedures therefore expand to include PQ key lifecycle management.

---

## 7. Future work

Event-signature migration remains unresolved, and state signing rides on the same sigKey — both migrate together on a separate track.

How that future work interacts with this proposal depends on which PQ signature scheme is selected:

- **If ML-DSA is selected**: this proposal facilitates adoption. The roster already carries an ML-DSA key, BCJSSE / BC providers are already wired, and key-generation tooling exists. Reusing the existing key (or generating a second ML-DSA key for events) is a configuration decision rather than new infrastructure.
- **If Falcon/FN-DSA or another scheme is selected**: possible solutions are adding a second PQ key field to the roster, or rekeying the one introduced here. Either branch depends on:
  - Java implementation availability for the chosen scheme (ACCP &/Or BCJSEE).
  - NIST standardization progress (FIPS 206 for Falcon is still draft).

This proposal intentionally avoids coupling transport migration to either branch.

---

## 8. Open decisions

The team must close the following before Phase 1 begins:

| # | Decision | Owner | Notes                                                                                                |
|---|---|---|------------------------------------------------------------------------------------------------------|
| 1 | Endorse this proposal as the path forward | Consensus team | Acceptance of direction; engineering sizing follows                                                  |
| 2 | ML-DSA parameter set (44 / 65 / 87) | Cryptography team / leadership | Experiments used 65; lower trades security for size, higher trades cost for margin                   |
| 3 | Keystore format under BCJSSE | Platform team | Verify whether PKCS12 works under BCJSSE before PQ implementation. if not, BKS migration is in scope |
| 4 | Standards-tracking owner for `draft-ietf-tls-mldsa` | Engineering management | Ongoing operational role                                                                             |
| 5 | Migration cadence: per-phase soak windows, mixed-mode duration | Operations team | Affects rollback complexity                                                                          |

---

## Appendix A. External references

- **RFC 8446** — TLS 1.3 — https://datatracker.ietf.org/doc/html/rfc8446
- **draft-ietf-tls-mldsa** — ML-DSA in TLS — https://datatracker.ietf.org/doc/html/draft-ietf-tls-mldsa
- **NIST FIPS 203** — Module-Lattice Key Encapsulation Mechanism (ML-KEM) — https://csrc.nist.gov/pubs/fips/203/final
- **NIST FIPS 204** — Module-Lattice Digital Signature Algorithm (ML-DSA) — https://csrc.nist.gov/pubs/fips/204/final
- **JEP 527** — Post-quantum hybrid key exchange in JDK — https://openjdk.org/jeps/527
- **BouncyCastle** — https://www.bouncycastle.org/
- **Amazon Corretto Crypto Provider** — https://github.com/corretto/amazon-corretto-crypto-provider
- **ML-DSA** — https://openquantumsafe.org/liboqs/algorithms/sig/ml-dsa.html

---

## Appendix B. Glossary

- **agrCert** — Agreement certificate. Ephemeral, regenerated at each node startup, presented as the node's TLS handshake identity. Today: EC-384, signed by the sigKey.
- **agrKey** — Private key paired with the agrCert.
- **BCJSSE** — BouncyCastle's JSSE provider implementation.
- **CertificateVerify** — A TLS 1.3 handshake message in which a peer signs the handshake transcript with its certificate's private key, proving possession of that key.
- **DAB** — Dynamic Address Book. The transaction family (`nodeCreate`, `nodeUpdate`) that updates roster entries.
- **gossip_ca_certificate** — Field in `RosterEntry` carrying the DER bytes of the sigCert. The classical trust anchor for transport.
- **handshake** — The cryptographic exchange at the start of a TLS connection.
- **hybrid (key exchange)** — A key-exchange construction that combines a classical scheme (x25519) with a PQ scheme (ML-KEM-768) such that the resulting shared secret is at least as strong as the stronger of the two.
- **mldsa44 / mldsa65 / mldsa87** — TLS signature scheme identifiers for the three NIST-defined ML-DSA parameter sets.
- **ML-DSA** — Module-Lattice Digital Signature Algorithm (NIST FIPS 204). The PQ signature algorithm used for authentication in this proposal.
- **ML-KEM** — Module-Lattice Key Encapsulation Mechanism (NIST FIPS 203). The PQ key-exchange primitive.
- **PKIX** — Public-Key Infrastructure for X.509 certificates (RFC 5280).
- **pq_gossip_ca_certificate** — New field proposed for `RosterEntry`. DER-encoded ML-DSA self-signed certificate (~5 KB at the 65 parameter set). Same encoding shape as the classical `gossip_ca_certificate` — the field name predates the decision to store a full cert and is retained for compatibility, even though the content is a certificate rather than a bare key.
- **PSS** — Probabilistic Signature Scheme. The RSA padding mode required for handshake signatures in TLS 1.3.
- **roster** — The on-state list of consensus nodes participating in the network. The source of transport identity.
- **sigCert** — Self-signed certificate published in the roster as `gossip_ca_certificate`. The trust anchor for transport. Today: RSA-3072.
- **sigKey** — Private key paired with the sigCert. Signs agrCerts at startup, signs consensus events, signs state hashes.
- **trust anchor** — In PKIX, a self-signed certificate (or its public key) that is trusted absolutely; cert chains terminate when they match a trust anchor.
- **X25519MLKEM768** — TLS named group identifying the hybrid x25519 + ML-KEM-768 key-exchange construction.