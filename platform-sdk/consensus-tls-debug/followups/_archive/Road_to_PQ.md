# Road to Post-Quantum TLS

## Goal

Enable post-quantum-safe gossip transport incrementally while minimizing changes in the existing signing infrastructure, preserving compatibility during migration, and avoiding dependence on future JDK timelines.

The proposal introduces post-quantum-aware TLS into the gossip layer while preserving existing event signing mechanisms.

---

# Summary

The proposal introduces a second identity into gossip transport and evolves the trust model from classical-only TLS identities to hybrid PQ-aware identities.

* Introduces post-quantum TLS authentication and hybrid key exchange into gossip transport.
* Replaces the default Java TLS provider stack with one capable of PQ TLS.
* Adds a second transport identity to nodes during migration.
* Evolves the transport trust model to include new PQ identities.
* Preserves existing event / state signing behavior.
* Enables incremental rollout using dual classical + PQ authentication.

The design intentionally separates:

* Transport security migration
* Event signing migration
* Future cryptographic agility decisions

This allows the platform to move toward PQ-safe transport independently.

---

# What Changes in the System

* TLS provider stack
* Node identity material
* Roster schema (one new field)
* Certificate generation
* Trust-store construction
* TLS negotiation policy
* Node provisioning
* Runtime crypto assumptions
* Deployment pipeline requirements

This does *not* change:

* Consensus behavior
* State hashing
* Application protocol behavior
* Event signing
* State signing
* Existing event signature verification
* Gossip protocol semantics

---

# Architectural Impact

## System assumptions that no longer hold

### TLS providers are no longer interchangeable

The system currently assumes SunJSSE and provider compatibility.

PQ TLS requires BCJSSE semantics, explicit provider routing, and provider-order awareness.

---

### TLS identities are no longer classical-only

Nodes gain a second transport identity during rollout.

The existing classical agreement certs remains valid during migration while ML-DSA identities are introduced incrementally.

---

### Trust-store generation extends to a second roster-anchored key

The roster has always been the effective trust root for transport: `gossip_ca_certificate` from each `RosterEntry` is loaded into the JSSE trust store and serves as the trust anchor for PKIX path validation on every handshake.

The migration extends this to a second roster field (`pq_gossip_public_key`) used to validate ML-DSA agreement certificates. Trust derivation remains PKIX-based; the chain widens to accept ML-DSA signatures alongside classical ones during rollout.

---

### Provider ordering becomes operationally significant

Incorrect ordering can silently disable ML-KEM support. The dedicated "Provider Ordering Constraints" section below covers the routing rules and the custom `JcaJceHelper` that implements them.

---

### Native crypto becomes part of runtime assumptions

Introducing ACCP adds:

* Platform-specific native dependencies
* Native library loading
* Architecture-specific deployment concerns
* JVM native-access requirements

---

# Trust Model Evolution

## Current model

Today:

* TLS trust derives entirely from classical PKI material.
* Agreement certificates are classical.
* Trust validation depends only on classical certificate chains.

---

## Proposed model

After migration:

* Roster state distributes PQ transport identities alongside the existing classical CA material.
* TLS authentication validates ML-DSA certificates against roster-published PQ keys.
* Classical and PQ trust paths coexist during migration.
* Trust-store generation consumes both classical and PQ identity material.

The roster, already the effective transport trust root, gains an additional key type used during PKIX validation.

---

# Architectural Strategy

The proposal intentionally separates:

| Concern            | Strategy                              |
| ------------------ | ------------------------------------- |
| Event signing      | Preserve existing scheme              |
| Gossip transport   | Migrate to PQ-capable TLS             |
| TLS authentication | Add ML-DSA support                    |
| Key exchange       | Introduce hybrid PQ exchange          |
| Rollout            | Dual classical + PQ transition        |
| Performance        | Accelerate classical crypto with ACCP |

This preserves crypto agility and avoids coupling transport migration to future event-signature decisions.

---

# Ecosystem Constraints

## Java ecosystem status

Java 27 introduces hybrid PQ key exchange support through JEP 527.

However:

* It only addresses the TLS key exchange phase.
* PQ TLS authentication is not included.
* ML-DSA certificate authentication is not supported by the default JSSE implementation.
* No JEP currently exists for PQ TLS authentication.

As a result, the default Java TLS stack is insufficient for full PQ TLS deployment.

---

## Standards maturity

ML-DSA TLS authentication remains draft-standardized.

The IETF work is still evolving and default JDK support is unlikely in the short term.

This introduces interoperability and draft-evolution risk that must be accepted explicitly.

---

## Falcon status

Falcon/FN-DSA remains immature from a TLS ecosystem perspective.

Currently:

* No TLS draft exists for Falcon authentication.
* No TLS signature scheme identifiers are assigned.
* Java ecosystem support remains minimal.

As a result, Falcon-based event signing remains future work and is intentionally decoupled from this proposal.

---

# Proposed Technical Direction

## Core design

The proposed stack uses:

| Component        | Purpose                       |
| ---------------- | ----------------------------- |
| BCJSSE           | Mandatory PQ TLS support      |
| BouncyCastle ML-KEM | Hybrid PQ key exchange     |
| ML-DSA           | PQ TLS authentication         |
| ACCP             | Classical crypto acceleration |

SunJSSE cannot provide:

* ML-KEM TLS negotiation
* ML-DSA TLS authentication
* PQ TLS certificate handling

BCJSSE is therefore a hard requirement for PQ transport.

---

# Which flavor of ML-DSA?
inal parameter-set selection remains open.
The current experiments used ML-DSA-65 because it provides a balanced tradeoff between security level, signature size, and verification cost for transport authentication workloads.
ML-DSA-44 provides smaller artifacts but a lower security level.
ML-DSA-87 increases computational and bandwidth costs without clear operational benefit for transport authentication.

---

# Provider Architecture

## BCJSSE

BCJSSE becomes the TLS implementation layer.

It provides:

* TLS 1.3
* Hybrid PQ key exchange
* ML-DSA TLS authentication
* Draft ML-DSA wire-format support

---

## ACCP

ACCP is optional from a correctness perspective.

It provides:

* Classical crypto acceleration
* Faster RSA operations
* Faster TLS handshakes
* Native-backed cryptographic implementations

The PQ migration can proceed without ACCP.

ACCP exists to reduce operational overhead and improve throughput.

---

# Provider Ordering Constraints

Provider ordering becomes a first-class operational concern.

BCJSSE silently disables ML-KEM support if another provider registers ML-KEM primitives ahead of BC.

This means:

* Provider routing can no longer be implicit.
* Provider ordering must become deterministic.
* Hybrid provider helpers become required infrastructure.

The proposal therefore introduces a custom JcaJceHelper implementation that:

* Routes ML-KEM operations explicitly to BC
* Allows classical operations to flow through ACCP
* Preserves PQ TLS functionality while retaining acceleration

This behavior is operationally critical and must remain stable across upgrades.

---

# Rollout Model

The migration intentionally uses a dual-authentication transition strategy.

## Phase 1 — Classical-only baseline

* Introduce BCJSSE
* Introduce ACCP
* Switch agrCert signing to RSA-PSS (required by BCJSSE for the legacy chain; sigCert unchanged)
* Preserve classical TLS auth
* Preserve existing identities

---

## Phase 2 — PQ-capable transport

* Add pq_gossip_public_key
* Generate ML-DSA identities
* Deploy hybrid-capable TLS stack
* Continue classical authentication

---

## Phase 3 — Dual-authentication window

* Accept classical and ML-DSA TLS auth
* Populate roster PQ identities
* Rebuild trust stores using PQ material

---

## Phase 4 — PQ-required transport

* Require ML-DSA TLS authentication
* Continue hybrid key exchange
* Retire classical TLS auth paths

---

## Phase 5 — Future event-signature migration

Out of scope for this proposal.

Future work may:

* Preserve RSA event signatures
* Move to Ed25519
* Introduce Falcon/FN-DSA
* Unify signing identities

The transport migration intentionally does not depend on these decisions.

---

# System Impact by Subsystem

| Subsystem            | Impact   |
| -------------------- | -------- |
| Gossip TLS           | Major    |
| Certificate tooling  | Moderate |
| Provisioning         | Moderate |
| Deployment pipeline  | Major    |
| Roster schema        | Moderate |
| SDK decoding         | Minor    |
| Consensus            | None     |
| State hashing        | None     |
| Event signing        | None     |
| Application protocol | None     |

---

# Detailed System Changes

## Platform TLS

The TLS stack transitions from SunJSSE to BCJSSE.

This requires:

* JSSE provider replacement
* TLS configuration rewrites
* Named-group configuration
* Signature-scheme configuration
* TLS factory changes
* Trust manager updates
* Key manager updates
* Provider-aware crypto routing

The stack enables:

* X25519MLKEM768 hybrid key exchange
* ML-DSA TLS authentication
* TLS 1.3 compatibility

---

## Certificate generation

The agreement certificate chain changes structurally, but the impact is narrower than initially expected.

### Existing behavior

* Self-signed sigCert (CA): SHA384withRSA, PKCS#1 v1.5
* Agreement cert (agrCert): SHA384withRSA, PKCS#1 v1.5, signed by the sigKey
* Both rotate together because both share the same signing algorithm

### New behavior

* Self-signed sigCert (CA): **unchanged** — keeps PKCS#1 v1.5
* Agreement cert (agrCert): SHA384withRSAandMGF1 (RSA-PSS), signed by the sigKey
* For PQ authentication: separate ML-DSA certificate chain runs in parallel

### Why the sigCert can stay on PKCS#1 v1.5

BCJSSE applies the connection's permitted-signature-scheme list to every certificate in the chain — stricter than RFC 5280's PKIX, which doesn't validate trust-anchor self-signatures. However, RFC 8446 §4.2.3 explicitly allows `rsa_pkcs1_*` schemes in `signature_algorithms` (and `signature_algorithms_cert`) for backward compatibility with legacy cert chains, while forbidding them for handshake `CertificateVerify` signatures.

Advertising `rsa_pkcs1_sha384` in the TLS `signatureSchemes` configuration therefore lets BCJSSE accept a PKCS#1 v1.5 self-signed CA in the chain without weakening handshake security — the protocol mandates PSS or ECDSA / Ed25519 for the actual handshake signatures.

This has been verified end-to-end against BCJSSE TLS 1.3 with the same gossip key types (RSA-3072 sigKey, EC-384 agrKey).

### Practical implications

* No fleet sigCert refresh is required for the BCJSSE migration.
* The `gossip_ca_certificate` DER bytes in roster state remain stable across the transition.
* Certificate generation tooling changes only the agrCert signing path: `SHA384withRSA` → `SHA384withRSAandMGF1`.
* TLS configuration adds `rsa_pkcs1_sha384` to `signatureSchemes` (cert-chain compat only).

What still requires tooling changes:

* `pcli generate-keys` (or equivalent) for the legacy chain to switch agrCert signing to PSS — code change only, no key change.
* New ML-DSA keypair generation path for PQ identities, separate from the legacy chain.

---

## Keystore changes

The proposal transitions keystore handling from PKCS12 to BKS.

This is driven primarily by:

* BCJSSE compatibility
* ML-DSA support requirements
* Provider interoperability consistency

---

## Roster and protobuf changes

A new field is introduced:

* pq_gossip_public_key

Affected structures:

* RosterEntry
* Node
* NodeCreateTransactionBody
* NodeUpdateTransactionBody

The field remains optional during rollout.

Eventually:

* PQ-aware trust validation depends on it
* All consumers must understand it

---

## State migration

The migration requires:

* Schema version updates
* State migration logic
* Roster validation updates
* Node update validation changes
* Fee schedule review

Existing nodes initially receive empty PQ fields.

Nodes populate PQ identities incrementally through nodeUpdate transactions.

---

## Gossip trust path

Trust-store generation evolves to consume:

* Existing gossip CA material
* PQ roster identities

During migration:

* Classical and PQ signature schemes coexist
* Trust stores accept both trust paths

Eventually:

* Classical TLS authentication paths are retired

---

# Runtime and Deployment Changes

## New runtime dependencies

* BCJSSE
* BouncyCastle TLS libraries
* ACCP
* Native ACCP artifacts

---

## Native runtime requirements

ACCP introduces:

* Native library loading
* Platform-specific packaging
* JVM native-access requirements

Required JVM flag:

```text
--enable-native-access=ALL-UNNAMED
```

---

## Deployment pipeline impact

The deployment pipeline must:

* Build platform-specific ACCP artifacts
* Distribute architecture-matching binaries
* Handle host/container architecture mismatches
* Validate native loading behavior

Operational complexity increases materially compared to the current pure-Java stack.

---

# Performance Characteristics

## High-level observations

The experiments indicate:

* PQ handshake overhead is operationally modest
* ACCP significantly accelerates classical cryptography
* BCJSSE performance is comparable to SunJSSE
* ML-DSA authentication is viable for transport workloads

---

## TLS handshake observations

| Path                   | PQ KX | PQ Auth | Mean Latency |
| ---------------------- | ----- | ------- | ------------ |
| SunJSSE                | No    | No      | 5.08 ms      |
| SunJSSE + ACCP         | No    | No      | 1.76 ms      |
| BCJSSE + BC            | Yes   | No      | 3.16–3.25 ms |
| BCJSSE + ACCP          | Yes   | No      | 2.26–2.56 ms |
| BCJSSE + ACCP + ML-DSA | Yes   | Yes     | 2.35–2.50 ms |

Observed on macOS arm64.

---

## Operational interpretation

The data suggests:

* Hybrid PQ key exchange introduces manageable overhead
* ML-DSA authentication is not operationally prohibitive
* ACCP offsets much of the TLS overhead introduced by PQ migration

---

## Existing workload acceleration

Under existing classical workloads:

* RSA throughput improves substantially under ACCP
* Ed25519 sees smaller but measurable gains

This means ACCP provides immediate operational value even before PQ rollout begins.

---

# Permanent vs Transitional Architecture

## Permanent

* BCJSSE adoption
* PQ-aware transport
* Hybrid TLS support
* Roster-distributed PQ identities
* TLS 1.3 migration
* Provider-aware crypto routing

---

## Transitional

* Dual classical + PQ auth acceptance
* Optional pq_gossip_public_key
* Classical TLS fallback
* RSA-PSS on agrCert (retires when the classical chain retires in Phase 4)
* Parallel trust paths

These transitional mechanisms exist solely to support phased rollout.

---

# Challenges

* IETF drafts may evolve
* Interoperability expectations may shift
* JDK support timelines remain uncertain
* Native dependency management becomes required
* Provider ordering becomes critical
* Rollout coordination complexity increases
* ACCP PQ support requires custom builds
* Provider integration behavior may drift over time
* TLS ecosystem behavior may evolve independently from the platform

---

## Future work

Event-signature migration remains unresolved, and state signing rides on the same sigKey — both migrate together on a separate track.

How that work interacts with this proposal depends on which PQ signature scheme is selected:

* **If ML-DSA is selected**: this proposal facilitates adoption. The roster already carries an ML-DSA key, the BCJSSE / BC providers are already wired, and key-generation       
  tooling exists. Reusing the existing key (or generating an ephemeral agreement key ML-DSA key for events) does not require new infrastructure.
* **If Falcon/FN-DSA or another scheme is selected**: we can choose to add another key type to the roster, or rekeying the one introduced here, or the original signing key.
Either branch
  depends on:
    * Java implementation availability for the chosen scheme
    * NIST standardization progress

The proposal intentionally avoids coupling transport migration to either branch.

---

# Open Decisions

The following strategic decisions remain open:

* Preserve RSA event signatures or migrate to Ed25519 first?
* Unify signing and agreement identities?
* ML-DSA flavor
* Roll out gradually or perform a coordinated migration?
* How aggressively should classical fallback paths be retired?

---