# PQ TLS Migration — Change Document

**Audience**: technical decision-makers (Leemon, Richard, platform leads)
**Purpose**: pick a path. This document says *what would change across the system* for each option so the team can choose with eyes open. It is **not** an engineering estimate (effort, calendar, sequencing depend on the path chosen) and **not** a technical brief (it summarizes findings rather than re-litigating the experiments).

---

## 1. Decision required

The team must agree on **one** of five paths before engineering begins:

> **How quantum-resistant must gossip TLS be, and when?**

Three of the five paths have **no roster schema change**. Two require **a new public-key field in HAPI**, which is the largest blast radius in this document and the main reason we're writing for decision-makers rather than just shipping.

---

## 2. Threat model in one paragraph

A future quantum adversary defeats TLS in two distinct ways. **Real-time impersonation**: a live quantum computer forges a `CertificateVerify` signature mid-handshake and MITMs a peer — solved only by ML-DSA (or another PQ signature) in authentication. This is Leemon's stated objective and the threat that motivates this work. **Harvest-now-decrypt-later**: today's encrypted gossip is recorded and decrypted in 2030+ once x25519 is broken — solved by ML-KEM in key exchange. Several cloud vendors are shipping "PQ-only" stacks aimed at this second threat, but **the harvest-now framing does not apply to Hedera in the same way**: gossip becomes public at consensus time anyway, so post-hoc confidentiality is not a strong requirement. Reviewers should not weigh kx-only paths (B / C / E) as if they solved our actual concern; they don't. They solve a concern we don't have.

Empirical confirmation that the signature check is load-bearing today: corrupted-signature and rogue-CA debug experiments both **fail** at handshake time. The framework verifies the agrCert's signature against the trust anchor on every connection. There is no current "match-bytes-against-state" mode masking the signature dependency.

---

## 3. The five paths, in one table

Verified end-to-end (in-process and against OpenSSL) for paths A–D. Path E is projected from JEP 527's specification.

| # | Path | PQ kx | PQ auth | New HAPI field | Latency (macOS arm64) | Ships when |
|---|---|---|---|---|---|---|
| **A** | SunJSSE + ACCP, classical only | ✗ | ✗ | No | **1.76 ms** | Today |
| **B** | BCJSSE pinned to BC, no ACCP | ✓ | ✗ | No | 3.16 / 3.25 ms | Today |
| **C** | BCJSSE + hybrid helper + ACCP | ✓ | ✗ | No | **2.26 / 2.56 ms** | Today |
| **D** | Path C + ML-DSA-65 certs | ✓ | ✓ | **Yes** | 2.35 / 2.50 ms | Today + roster migration |
| **E** | Wait for JDK 27 + ACCP | ✓ | ✗ | No | ~1.8 ms (projected) | ~late 2026, then ML-DSA never (no JEP) |

Numbers are mean handshake latency, 500 iterations × 3 trials, on M-series Mac. Linux/x86_64 numbers are pending and may shift the absolute values but not the relative ordering. PQ is verified with `openssl s_server -groups X25519MLKEM768`.

**Reading this table**: only Path D addresses the threat we care about. Paths B / C / E address key exchange (the cloud-vendor concern) and leave authentication classical.

---

## 4. System-wide impact at a glance

Each cell summarizes the subsystem-level work for that path. **Cells in bold are the items that distinguish that path from the previous one** — they're where new effort lives, not where existing effort applies.

| Subsystem | A (classical+ACCP) | B (BCJSSE) | C (BCJSSE+ACCP) | D (full PQ) | E (wait) |
|---|---|---|---|---|---|
| Platform TLS code | ACCP startup hook (1 line) | **Rewrite TlsFactory, KMF/TMF, keystore type** | C = B + **hybrid helper (~250 lines)** | C + **ML-DSA cert path** | JDK upgrade only |
| Cert generation (`pcli`) | None | **PSS signing** | **PSS signing** | C + **ML-DSA-65 keypair** | None |
| HAPI / protobuf | None | None | None | **`postQuantumGossipPublicKey` in `RosterEntry`, `Node`, `nodeCreate`, `nodeUpdate`** | None |
| State migration | None | **One-time cert refresh (data, not schema)** | Same as B | B + **schema bump for new field** | None |
| DAB transactions | None | None | None | **`nodeCreate` / `nodeUpdate` accept new field; fee schedule audit** | None |
| Gossip trust store | None | **Build from PSS-signed cert** | Same as B | B + **dual-algorithm trust store** | None |
| Mirror Node, Block Node, SDKs | None | None | None | **Roster parsers updated; SDK key types added** | None |
| Operator tooling | ACCP jar in deploy | New keystore format | New keystore format + ACCP | C + ML-DSA key files | JDK upgrade |
| Test fixtures | ACCP wired (already done in benchmark fixtures) | New cert chain | New cert chain | C + ML-DSA fixtures | None |
| External crypto deps | ACCP | BC, BCJSSE | BC, BCJSSE, ACCP | Same as C | None |

**The line that matters**: Paths A, B, C, and E all touch only the platform repo. **Path D is the only path that requires HAPI changes**, and HAPI changes mean coordinated work across Mirror Node, Block Node, every SDK, and operator tooling.

---

## 5. HAPI / ecosystem impact (Path D only)

Decision-makers asked specifically about adding a new key in HAPI specs. Here is what "add ML-DSA public key to roster" actually touches.

### 5.1 Protobuf surface

Three `.proto` files take a new field:

- `services/state/roster/roster.proto` → `RosterEntry` gets `bytes postquantum_gossip_public_key` (~5000 bytes — DER bytes of an ML-DSA-65 self-signed cert, same shape as `gossip_ca_certificate`)
- `services/state/addressbook/node.proto` → `Node` mirrors the same field (state representation)
- `services/node_create.proto` → `NodeCreateTransactionBody` accepts the new field
- `services/node_update.proto` → `NodeUpdateTransactionBody` accepts a `BytesValue` wrapper for optional update

Every protobuf consumer regenerates. **Wire-format compatibility**: protobuf field addition is backward-compatible in both directions, so old SDKs can talk to new servers (ignoring the field) and vice versa, but **using the field requires every actor that signs or validates a roster entry to be upgraded coherently**.

### 5.2 Handler / state surface

- `NodeCreateHandler`, `NodeUpdateHandler` (in `hedera-addressbook-service-impl`) — add validation + field copy.
- Roster state services in `consensus-roster` — schema version bump; one-time migration to populate the field on existing entries.
- `RosterValidator` — new validation rule (well-formed ML-DSA-65 self-signed X.509 certificate parseable through `CertificateFactory`, ~5000 bytes, within budget).
- `Utilities.createPublicKeyStore` (gossip-impl) — extend to read the PQ key alongside `gossipCaCertificate`.

### 5.3 Per-node migration

A node that adopts ML-DSA needs to:

1. Generate an ML-DSA-65 keypair locally (one-time).
2. Submit a `nodeUpdate` carrying the self-signed cert.
3. Wait for state to propagate.
4. Restart with the new key wired into TLS.

Until **all** nodes have the field populated and have flipped to ML-DSA-validating TLS, the network operates in a mixed mode. Either we run a coordinated freeze + flip window, or we accept a dual-signing transition (advertise both classical and ML-DSA schemes in TLS until rollout is complete and then retire classical). The dual-signing approach is more operationally forgiving but extends the transition window.

### 5.4 Ecosystem coordination

| Actor | Change | Impact |
|---|---|---|
| Mirror Node | Roster parser updated | Block until upgraded — explorer / dashboards may show stale fields |
| Block Node | Roster parser updated | Same |
| Java SDK | New key type in `Key` model | Required if external clients consume rosters |
| Other SDKs (Go, JS, .NET, Rust, Python, Swift) | Same | Required for full compatibility |
| Operator tooling (`pcli`, `yahcli`) | New key flag, new file format | Required at provisioning time |
| Genesis network spec | New field in `genesis-network.json` | One-time |

This is the fundamental reason Path D is qualitatively different from A–C: **it is a network-wide coordinated change**, not a platform-team ship. The depth of impact across each of these consumers is not yet fully scoped.

### 5.5 Fee impact

Adding ~5000 bytes to `nodeCreate` / `nodeUpdate` transactions changes their byte cost. The fee schedule should be audited (`FeeBuilder` in `hapi-utils`) before launch. Likely a small adjustment, not a blocker, but a flagged action.

### 5.6 What stays the same

- Event signing keys (RSA-3072 today) are **independent** of gossip TLS keys. Path D can be done without touching event signing. The team has a separate plan for PQ event signing using a different scheme not yet implemented in Java; it is out of scope for this document.
- Existing `gossipCaCertificate` field is **kept**. ML-DSA augments, does not replace, so old paths continue to work during rollout.

---

## 6. Performance, in one paragraph

The performance argument is settled by the benchmarks: **PQ TLS is not a performance regression**. Path C (PQ key exchange + ACCP) is ~30% slower than Path A (classical + ACCP) at 2.26 ms vs 1.76 ms — a 500 µs absolute difference per handshake. Path D (full PQ) adds ~100 µs more. At Hedera handshake rates, this is below the noise floor of node-level CPU. ACCP **does** accelerate BCJSSE when wired through a custom hybrid `JcaJceHelper`; an earlier conclusion against including ACCP was retracted after follow-up experiments — the appendix lists previously-stated claims that no longer apply.

Linux/x86_64 numbers are pending and required before final commitment. Rough expectation: same relative ranking, possibly tighter absolute spread because AES-NI dominates more uniformly than Apple Silicon's AMX path.

---

## 7. Risks by path

| Risk | A | B | C | D | E |
|---|---|---|---|---|---|
| **Real-time quantum impersonation exposure** (the threat that drives this work) | **High** | **High** | **High** | None | **High**, indefinitely |
| Harvest-now-decrypt-later exposure (low priority — gossip is public anyway) | High | None | None | None | High until 2026/27 |
| BCJSSE upstream bugs / supply chain | None | Medium | Medium | Medium | None |
| ACCP native-library stability (already in production benchmarks) | Low | None | Low | Low | Low |
| IETF draft churn (`draft-ietf-tls-mldsa-00` → `-01`+) — ML-DSA wire format may shift | None | None | None | **Medium** | None |
| Ecosystem desync (Mirror/Block/SDK rollout drift) | None | None | None | **High** | None |
| Operational rollback complexity | Trivial | One-step | One-step | **Multi-step / coordinated** | Trivial |

The IETF risk is the one that's easy to underweight. ML-DSA in TLS today references draft-00. Drafts move. Code points are stable, but salt construction, hash binding, and similar wire details are not finalized. Shipping Path D means committing to track and update against the draft until the RFC lands (~2027 realistic).

---

## 8. Recommendation framing

This document does not name a single recommended path — that's the team's call. The framing for the conversation:

- **Path D is the only path that addresses the team's stated threat model.** Paths B and C address key exchange but not authentication; their limitation is structural, not a configuration knob. Paths A and E provide neither authentication nor a path to it within the next ~2 years.
- **If the team chooses to defer Path D**, the ordering should be **C → D**, not **A → C → D**. Path A's classical-only stack does not move us toward authentication PQ; Path C's BCJSSE migration does (it provides the JSSE provider, the keystore changes, and the cert-refresh experience that Path D builds on). Path B is dominated by C — slower with no compensating benefit.
- **Choosing C-then-D vs D-directly is an operational decision.** It depends on confidence that real-time impersonation is far off, team capacity for HAPI / ecosystem coordination this cycle, and tolerance for paying the BCJSSE migration cost twice.

---

## 9. Open decisions for the team

The platform team can take Path C unilaterally. The following decisions cannot be made by engineering and require explicit team alignment:

1. **Threat-model urgency**: how soon do we need to address real-time quantum impersonation? This is the C-vs-D fork.
2. **Acceptability of partial PQ**: Leemon previously stated that partial PQ (kx without auth) is not acceptable. Confirm or revise — that position effectively rules out Paths B / C / E as final destinations.
3. **HAPI coordination tolerance**: if Path D, are we willing to coordinate Mirror Node + Block Node + SDK upgrades, or do we want to defer until other HAPI changes can ride along?
4. **Standards-tracking commitment**: Path D means tracking `draft-ietf-tls-mldsa` revisions until RFC. Who owns this watch?
5. **FIPS / CNSA compliance requirement**: not a current driver, but if it becomes one, ML-DSA is FIPS-204 compliant (positive for D); ACCP-via-AWS-LC has a FIPS-certified path (positive for A/C/D); BCJSSE is BC-FIPS, separate distribution.

---

## 10. Scope of this document

This document is for decision-makers comparing alternatives. It deliberately does NOT cover:

- **Engineering estimates.** Effort, calendar, sequencing — those depend on the path chosen.
- **The technical why.** The full empirical investigation, with experiment-level evidence, lives separately.
- **Linux benchmarks.** All numbers below are macOS arm64. Linux/x86_64 numbers are pending and required before launch.
- **Code-level review notes.** Anything specific to debug-prototype code is out of scope here.

---

## 11. Next steps if a path is chosen

| If path chosen | First action |
|---|---|
| A | Wire ACCP at startup; refresh certs to PSS only if we want to keep Path E open later. |
| B | Begin the BCJSSE migration. ~1 sprint. |
| C | Begin BCJSSE migration with hybrid helper. ~1 sprint, code already prototyped. |
| D | Begin Path C **plus** open a HAPI design review for the new field. ~3–6 months end-to-end including ecosystem rollout. |
| E | Stop work. Re-evaluate when JDK 27 GA ships. |

---

## Appendix — Retractions and corrections

The following statements appeared in earlier analysis but have been **superseded** by later evidence. They are listed here so reviewers don't accidentally cite them:

- *"Drop ACCP from the BCJSSE migration plan"* — **retracted**. ACCP accelerates BCJSSE when routed through a custom hybrid `JcaJceHelper`. ACCP is now a hard requirement for any BCJSSE-based path.
- *"BCJSSE has a ~7% performance regression vs SunJSSE"* — **retracted**. BCJSSE pinned to BC is **faster** than SunJSSE (3.16 ms vs 5.08 ms) on the same hardware.
- *"BCJSSE+ACCP at 2.32 ms PQ"* — **retracted**. That measurement was a silent fallback to classical `secp384r1`, not actual PQ.
- *"BCJSSE must be pinned to BC"* (blanket form) — **retracted**. Only ML-KEM needs BC pinning; the hybrid helper is the more general solution.