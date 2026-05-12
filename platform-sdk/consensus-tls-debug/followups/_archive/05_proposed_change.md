# Proposed Change: Post-Quantum Gossip TLS

## Intent

Make consensus-node gossip mTLS quantum-resistant in both phases that matter: key exchange and certificate authentication. The proposed stack is BouncyCastle JSSE (BCJSSE) as the TLS provider, BouncyCastle's ML-KEM-768 for hybrid key exchange (`X25519MLKEM768`), ML-DSA-65 for certificate signing and verification, and the Amazon Corretto Crypto Provider (ACCP) for classical-crypto acceleration. SunJSSE on the current JDK supports neither ML-KEM nor ML-DSA in TLS, so the provider swap is a hard prerequisite — there is no JSSE-internal alternative and none in the published JDK roadmap that covers authentication PQ.

This document is a per-subsystem breakdown intended for effort estimation. Each section should be readable by the team that owns the corresponding code.

---

## What changes, by subsystem

### Platform TLS

- Replace the JSSE provider (`SunJSSE` → `BCJSSE`) using a constructor that takes an explicit BC reference plus a custom `JcaTlsCryptoProvider` returning a hybrid `JcaJceHelper`.
- Replace keystore type (`PKCS12` → `BKS`) and KMF/TMF type (`SunX509` → `PKIX`).
- Configure named groups: `X25519MLKEM768` plus `secp384r1` (BCJSSE couples some signature-scheme activations to named-group membership; the secp384r1 entry is structural, not a fallback).
- Configure signature schemes: classical entries plus `mldsa65` for the transition window; classical entries dropped after rollout completes.
- Register ACCP at JCA position 1.
- Implement a hybrid `JcaJceHelper` (~250 lines) that pins `ML-KEM*` lookups to BC and routes everything else through the global chain. Without this, ACCP cannot accelerate BCJSSE classical operations and BCJSSE silently disables ML-KEM if any non-BC provider in the chain registers an `ML-KEM` `KeyPairGenerator` ahead of BC.

### Certificate generation

- Cert signing algorithm: change from `SHA384withRSA` (PKCS#1 v1.5) to `SHA384withRSAandMGF1` (RSA-PSS) for the legacy chain — BCJSSE rejects PKCS#1 v1.5 in TLS 1.3 cert chains. This rewrites the DER bytes of every existing certificate and is required even before any PQ work.
- New cert chain: ML-DSA-65 self-signed CA, agreement cert signed by the ML-DSA-65 CA.
- Key generation tooling (`pcli generate-keys` or equivalent) grows a flag for ML-DSA-65 keypair generation and emits the new key files alongside existing ones.

### HAPI / protobuf

- New field `postquantum_gossip_public_key` (bytes, ~5 KB — DER-encoded ML-DSA-65 self-signed cert, same shape as `gossip_ca_certificate`) added to:
  - `RosterEntry` (state)
  - `Node` (state)
  - `NodeCreateTransactionBody` (DAB)
  - `NodeUpdateTransactionBody` (DAB, with `BytesValue` wrapper for optional update)
- Field is optional during rollout, required once every node has populated it.
- Wire compatibility: protobuf field addition is forward and backward compatible. Old consumers ignore the field; new consumers read it. The compatibility window covers the rollout but cannot be permanent — once trust validation depends on the field, all readers must understand it.

### State / migration

- Roster-service schema version bump.
- One-time state migration: existing roster entries get the new field as null/empty, populated as nodes submit `nodeUpdate` carrying their PQ key.
- `RosterValidator`: new validation rule (well-formed ML-DSA-65 public key, size within budget).
- `NodeCreateHandler` / `NodeUpdateHandler`: field validation and copy.
- Fee schedule: ~5 KB added to `nodeCreate` / `nodeUpdate` payloads — audit `FeeBuilder` for size-based components.

### Gossip trust path

- Trust-store construction reads both `gossipCaCertificate` (existing) and the new PQ public key.
- TLS handshake configured to accept both classical and ML-DSA signature schemes during the transition window.
- Trust store rebuilds on roster changes so newly-populated PQ keys are picked up without restart.
- Classical signature schemes retired after every node has flipped, gated by an explicit decision (config flag or governance step).

### Operator tooling

- Node-provisioning scripts: generate ML-DSA keypair, lay out new key files.
- DAB-transaction builders (yahcli or equivalent): flag to attach the new public key to `nodeUpdate`.
- Deployment pipeline: ship the ACCP platform-specific jar matching each target architecture (`linux-x86_64`, `linux-aarch_64`, `osx-*` for dev). Watch for module-path conflicts when host and container architectures differ.

### Ecosystem (cross-team, the long pole)

Every consumer of `RosterEntry` needs an update:

- Mirror Node — roster parser; explorer / API surfaces that expose roster.
- Block Node — roster parser.
- SDKs in Java, Go, JS, .NET, Rust, Python, Swift — `Key` model addition for ML-DSA-65, roster decoding.
- Genesis-network spec — new field included in seed configurations.

These releases must precede the consensus-side flip that makes the field load-bearing for validation. Backward compatibility on the wire holds throughout, but a roster validator that requires the field will reject entries from nodes that haven't populated it yet — which is why the rollout has a defined soak window in mixed mode.

### Tests

- Unit: provider selection, hybrid helper routing per algorithm, signature-scheme negotiation, named-groups configuration.
- Integration: regenerate gossip docker fixtures with ML-DSA cert chains.
- Interop: handshake against an OpenSSL peer configured with `mldsa65`. This catches wire-format-correctness regressions that pure in-process tests can mask.
- Negative: corrupted ML-DSA signature, rogue ML-DSA CA — confirm the framework rejects.
- Soak: long-running handshake stress (millions of handshakes) to flush native-library leaks, JIT regressions, GC pressure surprises.

---

## New runtime dependencies

- BouncyCastle provider (`bcprov`)
- BouncyCastle JSSE (`bctls`)
- ACCP, with platform-specific classifier per target architecture
- JVM flag: `--enable-native-access=ALL-UNNAMED` (ACCP loads a native library)

---

## Gotchas worth flagging

- **Silent fallback in BCJSSE.** If the JCA helper isn't pinned correctly, BCJSSE silently disables `X25519MLKEM768` and the handshake falls back to classical with no error. The hybrid helper is the only configuration that delivers real PQ key exchange together with ACCP acceleration. Without it, ACCP and PQ are mutually exclusive in BCJSSE.
- **ML-DSA wire format is pre-RFC.** The current reference is an IETF draft. Code points are stable; salt and hash-binding details may shift across draft revisions. The team takes on a standards-tracking responsibility — schedule periodic BC/BCJSSE bumps until the RFC publishes (likely 2027).
- **Cert refresh is irreversible per node.** Once `gossipCaCertificate` is regenerated with PSS or ML-DSA signing, rolling back a node means reissuing keys and submitting another `nodeUpdate`. Plan rollout in waves with verifiable health checkpoints.
- **Mixed-mode soak window.** During rollout, both classical and ML-DSA must be acceptable in the trust path. The window has to last until every node has the new key populated; closing it prematurely fragments the network.
- **ACCP `KeyFactory.Ed25519` is not registered.** Currently harmless (consensus signing path uses `Signature`, not `KeyFactory`), but worth grepping production code for any `KeyFactory.getInstance("Ed25519", ...)` that would silently fall through.

---

## Performance

Mean handshake latency on Apple Silicon dev hardware: ~2.5 ms with full PQ, vs ~1.8 ms classical with ACCP. Difference is below the noise floor of node-level CPU at production handshake rates. ACCP also accelerates event signature verification on the consensus hot path, so the dependency pays for itself beyond TLS. Linux x86_64 production numbers are pending and required before launch; the relative ranking is expected to hold.

---

## Out of scope

- **Event signing keys.** Stay on the current scheme. A separate PQ scheme is planned for event signing using a different algorithm whose Java implementation is not yet available; that work is on its own track.
- **JDK upgrade.** This change works on the current JDK; it does not depend on a future release.
- **BC-FIPS distribution.** Standard BCJSSE is sufficient. FIPS-certified variants are a separate decision if compliance becomes a requirement.

---

## What to size

For each subsystem above, please return:

1. Implementation effort (eng-weeks).
2. Test surface (new tests + regression risk on existing tests).
3. Coordination cost (cross-team dependencies that gate your subsystem).
4. Rollout risk (worst-case if the change misbehaves mid-flight).

The platform TLS work, cert generation, and gossip trust path are contained within the consensus codebase and can be sized in the normal way. The HAPI proto change and the ecosystem rollout are coordination-heavy and benefit most from per-team sizing rather than a single platform-side estimate. Standards-tracking ownership is an ongoing operational cost worth pricing separately from one-shot implementation effort.