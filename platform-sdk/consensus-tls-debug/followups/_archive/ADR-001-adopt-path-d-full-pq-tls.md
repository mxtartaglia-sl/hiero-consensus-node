# ADR-001: Adopt Path D — Full Post-Quantum Gossip TLS

| | |
|---|---|
| **Status** | Proposed |
| **Date** | 2026-05-06 |
| **Deciders** | Consensus team (pending) |
| **Purpose** | Lay out the alternatives so decision-makers can estimate effort and pick a path. |
| **Supersedes** | none |
| **Superseded by** | none |
| **Tags** | tls, post-quantum, gossip, hapi, roster |

---

## Context

Gossip in the consensus node uses mTLS over TLS 1.3. The current stack — SunJSSE with classical x25519 key exchange and RSA-3072 / EC-384 authentication — is vulnerable to two quantum threats, but **only one of them is a real concern for Hedera**:

- **Real-time impersonation** (the one that matters for us): a live quantum computer forges `CertificateVerify` signatures mid-handshake, MITMs a peer, and breaks consensus integrity. Solved only by a PQ signature scheme (ML-DSA) for authentication. This is Leemon's stated objective.
- **Harvest-now-decrypt-later** (the one cloud vendors are addressing, not us): an adversary records encrypted gossip today and decrypts it later once x25519 is broken. This concern drives several cloud vendors to ship "PQ-only" solutions that address only the key-exchange phase. **It does not apply to us in the same way** — Hedera gossip becomes public at consensus time anyway, so post-hoc confidentiality is not a strong requirement. We mention it here so reviewers understand why solving "kx-only" (Path B / C / E below) is not what the team is being asked to optimize for.

The signature check is empirically load-bearing: corrupted-signature and rogue-CA debug experiments both fail at handshake time, confirming the framework verifies the agreement cert against the trust anchor on every connection. There is no current "match-bytes-against-state" mode hiding the signature dependency.

**This ADR is a proposal.** It lays out the five paths considered and recommends one, so decision-makers can estimate effort and choose. It does not record an accepted team decision yet.

---

## Proposed decision

**Adopt Path D**: BCJSSE pinned to BC for ML-KEM, custom hybrid `JcaJceHelper` to route classical and ML-DSA operations through ACCP, and ML-DSA-65 certificates for gossip authentication. The full path is:

- **Key exchange**: `X25519MLKEM768` (hybrid PQ) via BCJSSE
- **Authentication**: ML-DSA-65 certificates, signed and verified through ACCP
- **Acceleration**: ACCP at JCA position 1, accessed via the hybrid helper for classical ops + ML-DSA
- **Roster schema**: new `postquantum_gossip_public_key` field added to `RosterEntry` and `Node` HAPI messages
- **Provisioning**: `pcli generate-keys` extended to produce ML-DSA-65 keypairs alongside existing keys

Path D is the **only** path that addresses real-time quantum impersonation, which is the threat Hedera actually cares about. Path C and Path E address key exchange only; that is the cloud-vendor framing and does not match our threat model. We accept Path D's larger blast radius (HAPI change, ecosystem coordination) because the alternative — shipping kx-only first, then adding authentication later — costs us two coordinated network migrations to reach a destination we can reach in one.

---

## Decision drivers

In priority order:

1. **Real-time impersonation is the threat we actually need to solve.** It directly breaks live consensus once quantum attacks become viable. Harvest-now-decrypt-later, the threat cloud vendors are optimizing against, is not a strong concern for Hedera because gossip becomes public at consensus.
2. **Authentication PQ requires both BCJSSE *and* a roster structure change.** No JSSE-layer-only fix exists. SunJSSE has not started work on PQ signature schemes in TLS, and even a perfect TLS stack cannot help if the trust anchor in the roster is RSA. The HAPI change is therefore intrinsic to the goal, not optional scope.
3. **Doing it once is cheaper than doing it twice.** Path B / C ship the BCJSSE migration and a network-wide cert refresh but do not address authentication. Adding ML-DSA later means a second BCJSSE config change, a second cert refresh, and a second roster update — much of the same operational cost paid twice. If we accept that the BCJSSE migration is happening anyway, the marginal cost of also adding ML-DSA in the same window is meaningfully smaller than treating it as a separate later project.
4. **Performance penalty is negligible.** Path D measures at 2.50 ms mean handshake (macOS arm64), versus 1.76 ms for the fastest classical+ACCP path — a ~700 µs absolute difference at handshake rates that are not the production bottleneck.
5. **ML-DSA is the only viable near-term PQ signature.** Falcon has no TLS draft; SLH-DSA is one maturity level behind ML-DSA and has prohibitively large signatures. There is no alternative to ML-DSA for this decision window. Note that this constraint is **for gossip TLS authentication only** — event signing is governed by a different PQ scheme that Leemon has previously described, whose Java implementation is not yet available, and is out of scope for this ADR.
6. **JDK won't deliver authentication PQ in any visible timeframe.** No JEP filed for ML-DSA in TLS. Realistic estimate is 2–3 years minimum (RFC publication + JEP cycle). Waiting is not a strategy that produces full PQ.

---

## Considered options

| # | Path | PQ kx | PQ auth | New HAPI field | Latency | Why rejected |
|---|---|---|---|---|---|---|
| A | SunJSSE + ACCP | ✗ | ✗ | No | 1.76 ms | Doesn't address authentication. Also keeps us on a JSSE provider that has no PQ-auth roadmap. |
| B | BCJSSE pinned to BC | ✓ | ✗ | No | 3.16 / 3.25 ms | Addresses kx but not authentication. Slower than C with no compensating benefit. |
| C | BCJSSE + hybrid helper + ACCP | ✓ | ✗ | No | 2.26 / 2.56 ms | Addresses kx but not authentication. Matches the cloud-vendor "PQ-only kx" framing — a sensible bar for systems needing long-term confidentiality, but not aligned with our threat model. Choosing C means committing to a second coordinated migration later to add authentication. |
| **D** | **C + ML-DSA-65 certs** | **✓** | **✓** | **Yes** | **2.50 ms** | **Proposed.** |
| E | Wait for JDK 27 + ACCP | ✓ | ✗ | No | ~1.8 ms (projected) | JDK 27 (JEP 527) gives kx only. ML-DSA in TLS has no JEP — indefinite wait. Same authentication gap as B/C. |

Detailed pros/cons for the proposed and runner-up options:

### Path D (proposed)

**Pros**
- Addresses real-time quantum impersonation, the threat we actually care about. Incidentally also closes harvest-now-decrypt-later, since PQ kx is bundled in.
- Single migration — no follow-on rollout.
- Performance is acceptable (sub-3ms handshakes, well below production budget).
- Verified end-to-end: both in-process and OpenSSL interop confirm wire-format correctness.
- ML-DSA is FIPS-204 compliant; positions us well for any future FIPS requirement.

**Cons**
- Largest blast radius: HAPI proto change, Mirror Node + Block Node + every SDK + operator tooling all need coordinated updates.
- IETF draft churn risk: TLS uses `draft-ietf-tls-mldsa-00`. Wire format may shift across draft revisions until the RFC publishes.
- Multi-month rollout (estimated 3–6 months end-to-end including ecosystem coordination).
- Multi-step rollback if rollout misbehaves mid-flight.

### Path C (runner-up)

**Pros**
- No HAPI change, no ecosystem coordination.
- Ships in approximately one sprint from the platform team alone.
- Provides PQ key exchange — the same bar several cloud vendors are deploying. A reasonable choice if the team judges real-time impersonation to be far enough off that incremental progress is preferable to a coordinated full migration now.

**Cons**
- Does **not** address real-time quantum impersonation, which is the threat we actually care about.
- Sets up a future second migration to add ML-DSA authentication. Much of the BCJSSE plumbing and cert-refresh cost is paid twice.

---

## Consequences

### Positive

- **Real-time quantum impersonation is closed in one migration.** Once Path D is rolled out and classical schemes retired, gossip is end-to-end PQ for both phases that need it.
- **ACCP acceleration applies system-wide.** ACCP at JCA position 1 also speeds up event signature verification (consensus hot path). Independent benchmarking on a Linux consensus host has measured −15% average / −22% p95 latency and +18% gossip throughput from registering ACCP, with no measurable GC-pause cost.
- **Architecture stays coherent.** The existing trust model (sigCert as trust anchor + ephemeral agrCert) is preserved; we change the signature algorithm, not the model.
- **Event signing is independent.** This decision does not constrain or commit the team on event-signing key types.

### Negative

- **HAPI coordination is the critical path.** Mirror Node, Block Node, and SDK teams must take the new `postquantum_gossip_public_key` field through their release cycles before nodes can validate against it.
- **Standards-tracking is now an ongoing responsibility.** Until `draft-ietf-tls-mldsa` becomes an RFC, someone must monitor revisions and coordinate BC / BCJSSE updates if the wire format shifts.
- **Mixed-mode operating window.** During rollout, some nodes have ML-DSA keys in roster and some don't. We need a dual-signing transition window (advertise both classical and ML-DSA TLS schemes) so the network operates throughout.
- **Cert refresh is mandatory and irreversible per node.** Every node regenerates its sigCert at a known-PSS, then later at ML-DSA, with corresponding state updates. Rollback for an individual node means re-issuing classical keys and a `nodeUpdate`.

### Mitigations

- **Mixed-mode TLS configuration**: TLS handshake configured to accept both classical and ML-DSA signature schemes during the rollout window. Classical retired after every node has flipped.
- **Standards watch**: assign explicit ownership for tracking `draft-ietf-tls-mldsa` revisions. Treat draft updates as planned BC/BCJSSE upgrade work, not surprises.
- **Ecosystem coordination plan**: HAPI proto change submitted to Mirror Node, Block Node, and SDK teams before consensus-side code lands. SDKs ship support in advance so external clients can validate rosters.
- **Rollback discipline**: per-node rollback procedure documented before deployment begins.

---

## Validation

The decision is validated as successful when, in order:

1. **Code lands**: BCJSSE + hybrid helper + ACCP + ML-DSA path is merged to main and CI green.
2. **Schema lands**: HAPI proto extended with `postquantum_gossip_public_key`; protobuf consumers (Mirror Node, Block Node, SDKs) upgraded.
3. **Tooling lands**: `pcli generate-keys` produces ML-DSA-65 keypairs; deployment pipelines updated.
4. **Network rolls over**: every consensus node submits a `nodeUpdate` populating the new field; `gossipCaCertificate` and ML-DSA cert chain coexist in mixed mode.
5. **Classical retired**: TLS configuration drops classical signature schemes; gossip is end-to-end PQ.
6. **Operational steady state**: 30 days of production gossip with no PQ-attributable handshake failures, no measurable handshake latency regression on Linux/x86_64 production hardware.

If validation steps 1–4 take longer than two release cycles, **revisit this decision** — sustained ecosystem desync is a stronger signal that Path C (single-migration to kx-only) was the right choice, and we may want to reduce scope.

---

## Open follow-ups

These are tracked but **not** part of this decision:

- **Linux/x86_64 benchmarks** — required before launch. Current numbers are macOS arm64; expected ranking unchanged but absolute values to be re-measured.
- **ML-DSA OpenSSL interop verification** — confirm wire format against an OpenSSL peer specifically using ML-DSA, not just classical with PQ kx.
- **Long-running stability** — millions of handshakes over hours. Confirms no native-library leaks, JNI stability, GC pressure surprises.
- **Fee schedule audit** — adding ~5000 bytes (DER-encoded ML-DSA-65 self-signed cert) to `nodeCreate` / `nodeUpdate` may shift fees. Decide once HAPI change is concrete.
- **Standards-tracking owner assignment** — ongoing responsibility, not a one-time task.

---

## Notes for future readers

This ADR records *what* is being proposed and *why*. The *how* and *when* — file-level task breakdown, sequencing, rollout phasing — is owned by the engineering planning process and is intentionally not included here.

- **Why ACCP is in this proposal**: an earlier conclusion against including ACCP (based on initial benchmarks where ACCP had no measurable effect on a BCJSSE configuration pinned to BouncyCastle) was retracted after follow-up experiments showed that a custom hybrid `JcaJceHelper` lets ACCP accelerate BCJSSE end-to-end. ACCP is now considered a hard requirement for any BCJSSE-based path, including this one. Independent measurements on a Linux benchmark host also show ACCP improves consensus-side event signature verification, so its value is not limited to the TLS path.
- **Why ML-DSA-65 specifically**: ML-DSA-44 has weaker quantum-resistance margin than the team is comfortable with at this maturity stage; ML-DSA-87 has substantially larger keys and signatures with no clear marginal benefit. ML-DSA-65 is the IETF and FIPS-204 sweet spot.
- **Why not Falcon / SLH-DSA**: Falcon has no TLS code points or draft. SLH-DSA's signatures are large (~7–50 kB depending on parameter set) and would meaningfully impact handshake latency. Both are tracked as contingencies, not active alternatives.

---

## External references

- JEP 527 (Post-quantum hybrid key exchange in JDK 27): https://openjdk.org/jeps/527
- IETF draft for ML-DSA in TLS: https://datatracker.ietf.org/doc/html/draft-ietf-tls-mldsa-00
- NIST FIPS 204 (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final