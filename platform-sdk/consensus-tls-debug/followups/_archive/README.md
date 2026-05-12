# PQ TLS Investigation — Follow-up Items

Master plan for the next round of investigation, split into three deliverables.

## Context

The initial investigation (see [`../INVESTIGATION.md`](INVESTIGATION.md) and [`../ACCP_STRATEGIES.md`](ACCP_STRATEGIES.md)) established:

- TLS 1.3 migration is trivial on SunJSSE, working end-to-end in gossip.
- BCJSSE pinned to BC is the only way to get real X25519MLKEM768 today on JDK 25.
- A custom `JcaJceHelper` unlocks ACCP acceleration for BCJSSE while preserving ML-KEM compatibility.
- Fully PQ TLS (ML-KEM + ML-DSA) works via BCJSSE + hybrid helper at ~2.5 ms mean latency on macOS arm64.
- BCJSSE is ~44% faster than SunJSSE for classical handshakes; ACCP doubles throughput on top of that.

The team has agreed on three follow-up items (this repo) plus one on Richard (TSS feasibility).

## Items

| # | Title | Owner | Est. effort | File |
|---|---|---|---|---|
| 1 | Java 27 / JEP 527 deeper investigation | Maxi | 4–8 hours | [`01_jdk27_research.md`](./01_jdk27_research.md) |
| 2 | Performance analysis: BC, BoringSSL, AWS-LC | Maxi | 1–2 days | [`02_performance_analysis.md`](./02_performance_analysis.md) |
| 3 | Systems-level PQ TLS specification (engineering estimation) | Maxi | 3–5 days | [`03_systems_spec.md`](./03_systems_spec.md) |
| 4 | TSS feasibility and timeline | Richard | — | external |
| 5 | Change document for decision-makers (system-wide impact, incl. HAPI) | Maxi | — | [`05_change_document.md`](./05_change_document.md) |
| ADR-001 | Adopt Path D — full post-quantum gossip TLS | Consensus team | — | [`ADR-001-adopt-path-d-full-pq-tls.md`](./ADR-001-adopt-path-d-full-pq-tls.md) |

## Sequencing

```
┌─────────────────────────────┐
│ 1. JDK 27 research          │ ← do first, reshapes the rest
│    (can we just wait?)      │
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│ 2. Performance analysis     │ ← fills benchmark gaps on
│    (Linux numbers, BoringSSL)│   production-relevant platforms
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│ 3. Systems-level spec       │ ← synthesizes findings into
│    (estimable engineering   │    a plan Richard can estimate
│    plan)                    │
└─────────────────────────────┘
```

Item 1 should complete before item 2 starts — if JDK 27 solves the authentication PQ problem, the benchmark scope narrows significantly. Item 3 needs both 1 and 2 to be grounded in evidence.

## Definition of done

- **Item 1**: a document answering "does waiting for JDK N give us everything we need, and when?" with concrete JEP references, timelines, and a clear verdict.
- **Item 2**: extended benchmarks including Linux x86_64 (production target), BoringSSL/AWS-LC direct, event signature verification, and long-running stability. Full comparison table.
- **Item 3**: a systems-level specification document covering architecture diagrams, per-system changes, sequencing plan, rollback strategy, test strategy, open questions. Detailed enough for Richard to estimate engineering work.