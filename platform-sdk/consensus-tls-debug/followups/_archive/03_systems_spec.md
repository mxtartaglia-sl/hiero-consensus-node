# Item 3: Systems-Level PQ TLS Specification

**Goal**: produce a formal engineering specification for the PQ TLS migration, detailed enough for Richard to estimate work.

**Owner**: Maxi
**Est. effort**: 3–5 days
**Status**: not started, depends on items 1 and 2

---

## What we already know

### Decision options on the table

From prior investigation, five viable paths have emerged. The specification needs to pick one (primary) and possibly a fallback.

| # | Path | PQ kx | PQ auth | Roster change | Code impact |
|---|---|---|---|---|---|
| A | SunJSSE + ACCP (classical now, JDK 27 for PQ later) | Wait for 27 | Wait indefinitely | Cert refresh only | Minimal |
| B | BCJSSE pinned to BC (PQ kx, classical auth) | ✓ | ✗ | Cert refresh only | Medium |
| C | BCJSSE + hybrid helper + ACCP (PQ kx, classical auth) | ✓ | ✗ | Cert refresh only | Medium + 250 lines helper |
| D | BCJSSE + hybrid helper + ACCP + ML-DSA certs (fully PQ) | ✓ | ✓ | **Schema change** | Large |
| E | Wait for JDK 27 + JEP 527 + ACCP | ✓ (on JDK 27) | ✗ | Cert refresh only | Minimal |

### Confirmed technical constraints

- TLS 1.3 migration itself is trivial on SunJSSE, non-trivial on BCJSSE (keystore type change, KMF/TMF change, signature algorithm change).
- BCJSSE rejects PKCS#1 v1.5 RSA signatures in cert chains — must switch to RSA-PSS.
- BCJSSE requires `secp384r1` in `namedGroups` for ECDSA signature schemes to activate (internal coupling).
- ML-KEM in BCJSSE only works when BCJSSE is pinned to BC OR via the custom hybrid `JcaJceHelper`.
- ML-DSA requires a new public-key field in the roster (`RosterEntry`).
- SunJSSE on JDK 25 does NOT support PQ in TLS.
- ACCP's native library requires `--enable-native-access=ALL-UNNAMED` on modern JDKs.

### Components affected

Any PQ TLS migration touches:

1. **Platform TLS code**:
   - `TlsFactory` (BCJSSE config, keystore type, named groups, signature schemes)
   - `ConsensusCryptoUtils.createKeyManagerFactory` (provider selection)
   - `CryptoConstants` (algorithm names, providers, keystore types)

2. **Certificate generation**:
   - `KeysAndCertsGenerator` (PSS signing, potentially ML-DSA)
   - `CertificateUtils.generateCertificate`
   - `pcli generate-keys` CLI

3. **State and roster**:
   - `RosterEntry` protobuf definition (for option D: new ML-DSA field)
   - `nodeCreate`, `nodeUpdate`, `registeredNodeCreate/Update` DAB transactions
   - State migration logic on the roster service
   - `gossipCaCertificate` cert refresh (all options)

4. **Gossip layer**:
   - `NetworkUtils.createSocketFactory` (pass additional parameters)
   - `InboundConnectionHandler` (peer identification if cert format changes)
   - `Utilities.createPublicKeyStore` (trust store construction from roster)

5. **Test fixtures**:
   - `otter` docker containers (experimental runtime)
   - `sloth` benchmark fixtures
   - `PreGeneratedX509Certs` test fixtures
   - All `TlsFactoryTest` and related unit tests

6. **Ecosystem**:
   - Mirror Node: parses roster, may decode certs
   - Block Node: parses roster
   - SDKs: may need new key types
   - Testnet/mainnet operator tooling: `pcli` variants, deployment scripts

---

## Specification outline

### Section 1: Executive summary

- One-paragraph recommendation
- Decision matrix: "if X, we should do Y"
- Key risks

### Section 2: Threat model and requirements

- Harvest-now-decrypt-later: what data must stay confidential for how long?
- Real-time quantum impersonation: realistic timeline assessment
- Performance requirements: handshake TPS, latency SLA, CPU budget
- Compliance: FIPS, CNSA Suite, anything else?
- Dependencies: must we wait for roster consensus mechanism? JDK LTS?

### Section 3: Proposed architecture

- Component diagram: before → after
- Data flow: key generation, roster update, handshake, event signing
- State schema changes (if option D)

### Section 4: Technology choices

- TLS stack (BCJSSE vs SunJSSE vs netty-tcnative)
- PQ algorithms (ML-KEM only, or ML-KEM + ML-DSA)
- ACCP inclusion (yes/no) with justification
- Key format (PEM, PKCS#12, BKS)
- Signature algorithms for cert chain (PSS, ML-DSA, Ed25519)

### Section 5: Required system changes

Organized by subsystem:

#### 5.1 Platform TLS
- Files to change: list with brief description
- API changes: new parameters, new constants
- Configuration surface: what operators can tune

#### 5.2 Certificate generation
- Algorithm change (PSS / ML-DSA)
- Tooling change (pcli, test fixtures)
- Backward compatibility: how to handle old cert formats during migration

#### 5.3 Roster / state
- Schema change (if D): new field definition, protobuf version bump
- Migration: existing rosters need to be upgraded
- Validation: DAB transaction handlers need new checks

#### 5.4 DAB transactions
- Per transaction: which fields added/changed
- Fee implications (if new cryptographic operations are expensive)
- Admin key requirements for key rotation

#### 5.5 Tooling
- `pcli generate-keys`: new key types
- Deployment scripts: provisioning new key files
- Mirror Node / Block Node / SDKs: roster parser updates

#### 5.6 Test coverage
- New unit tests for each component
- New integration tests (otter, sloth)
- Interop tests against OpenSSL PQ server
- Rollback / downgrade test scenarios

### Section 6: Rollout plan

- **Phase 0**: code changes land in dev. No user impact.
- **Phase 1**: cert refresh (PSS). All nodes regenerate sigCerts, submit node updates. Network-wide roster update.
- **Phase 2**: TLS stack migration (BCJSSE). Gossip uses new stack. Classical only at this point.
- **Phase 3**: Enable PQ key exchange (X25519MLKEM768). Config flip, no schema change.
- **Phase 4** (option D only): ML-DSA schema rollout. New field in roster. Dual-signing period. Eventual RSA retirement.

Each phase has:
- Code changes required
- Testing required
- Deployment steps
- Rollback procedure
- Success criteria

### Section 7: Risk register

- Technical risks (BCJSSE bugs, ACCP native library stability, JDK version drift)
- Operational risks (migration window, rollback complexity)
- Schedule risks (waiting for JDK 27, waiting for IETF standardization)
- Ecosystem risks (mirror node, SDK, block node coordination)

Each with likelihood × impact and mitigation.

### Section 8: Test strategy

- Unit test coverage target
- Integration test scenarios
- Interop test scope (OpenSSL, possibly other TLS stacks)
- Performance test scenarios (load, endurance, concurrent connections)
- Security review gates (external audit?)

### Section 9: Estimation inputs

Structured to make engineering estimation easy:
- Per-component task list
- Dependencies between tasks
- Skills required per task (Java networking, state migration, DAB, etc.)
- Calendar risks (wait periods, external approvals)

### Section 10: Open decisions for the team

Points where the spec can't decide and the team must choose:
- Option A vs Option D vs Option E
- ML-DSA or SLH-DSA (if full PQ)
- Keep RSA signing keys or migrate to Ed25519 classical first?
- FIPS compliance: required, or nice-to-have?
- Migration window: freeze all network changes during rollout, or allow concurrent changes?

---

## Inputs needed before writing

From item 1 (JDK 27 research):
- Definitive answer on whether JDK 27 will have ML-DSA in TLS
- JDK 27 GA timeline

From item 2 (performance analysis):
- Linux production numbers (not macOS)
- Cost breakdown: crypto as % of total node CPU
- ACCP benefit on Linux

From external (Richard / Rohan / Prachy):
- TSS timeline and strategy — affects whether PQ TLS is part of a bigger PQ migration
- Roster change feasibility and willingness
- Migration window availability

From Hedera governance / business:
- FIPS compliance requirements
- Deployment schedule constraints
- Acceptable risk tolerance

---

## Deliverable

A single formal spec document (`PQ_TLS_SPEC.md` or similar), organized by the section outline above. Target 15–25 pages (markdown). Structured for engineering review and work estimation.

To be reviewed by:
- Richard (tech lead / estimation)
- Platform architects
- Network engineering team
- Security review
- Ops team (for deployment feasibility)

---

## Working notes

Space reserved for working notes as the spec is drafted. Things to capture:

- Decisions made during drafting and their rationale
- Areas where further investigation is needed before deciding
- Feedback from reviews
- Revisions to earlier conclusions as more information comes in

---

## Document structure template

```
PQ_TLS_SPEC.md
├── 1. Executive summary
├── 2. Threat model and requirements
├── 3. Proposed architecture
│   ├── 3.1 Current state diagram
│   ├── 3.2 Target state diagram
│   └── 3.3 Migration state (during rollout)
├── 4. Technology choices
│   ├── 4.1 TLS stack
│   ├── 4.2 PQ algorithms
│   ├── 4.3 ACCP decision
│   ├── 4.4 Key and cert formats
│   └── 4.5 Signature algorithms
├── 5. System changes
│   ├── 5.1 Platform TLS
│   ├── 5.2 Certificate generation
│   ├── 5.3 Roster / state
│   ├── 5.4 DAB transactions
│   ├── 5.5 Tooling
│   └── 5.6 Test coverage
├── 6. Rollout plan
│   ├── 6.1 Phase 0: code
│   ├── 6.2 Phase 1: cert refresh
│   ├── 6.3 Phase 2: BCJSSE migration
│   ├── 6.4 Phase 3: PQ kx enable
│   └── 6.5 Phase 4: ML-DSA (if applicable)
├── 7. Risk register
├── 8. Test strategy
├── 9. Estimation inputs
└── 10. Open decisions
```