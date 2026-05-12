# Archive — superseded PQ TLS investigation documents

Everything in this directory is **superseded**. It is kept for historical reference only.

## Why these were archived

The investigation that produced these documents accumulated drift over its lifetime:

- Multiple parallel attempts at the same document (`RFC-001-pq-tls-transition.md`, `Road_to_PQ.md`, `f.md`, `f2.md`, `05_change_document.md`, `05_proposed_change.md`).
- Performance numbers measured under inconsistent harness configurations, leading to retraction of multiple specific claims (e.g., "BCJSSE+ACCP at 2.32 ms PQ" was a silent classical fallback; "BCJSSE has a 7% perf regression" was wrong; "drop ACCP from BCJSSE plan" was wrong).
- Inferred per-operation costs (e.g., "BC RSA-PSS verify is 8–12 ms") derived from queue-saturation dynamics in the consensus-sloth benchmark rather than direct measurement; later contradicted by handshake-total measurements.
- Stale IETF draft references (`draft-ietf-tls-mldsa-00`) cited as current when revision -03 was already in the IESG queue.
- Threat-model framings that conflated cloud-vendor concerns with consensus-specific concerns.

Rather than continue patching, the investigation was reset. A fresh measurement matrix was run on a single unified harness, and the canonical documents were rewritten from those measurements only.

## What is canonical now

See the parent `followups/` directory:

- `README.md` — top-level index
- `proposal.md` — single canonical proposal
- `performance.md` — only freshly-measured numbers, methodology stated, dated
- `findings.md` — empirical findings, each tagged with verification source
- `experiments.md` — catalog of debug variants in the `consensus-tls-debug` module

If a claim appears here in an archived document but **does not** appear in a canonical document above, it should be considered withdrawn.

## What stays valid here

- Background reading on the BCJSSE migration mechanics (`INVESTIGATION.md`)
- The hybrid `JcaJceHelper` rationale (`ACCP_STRATEGIES.md`)
- The IANA registry snapshot (`04_iana_signature_scheme_registry.md`) as of its date
- The consensus-sloth ACCP integration findings (`accp-integration.md`, `accp-benchmark-findings.md`) — note that the inferred per-op numbers were later questioned

These remain useful as historical record but their specific numbers should be cross-checked against the canonical `performance.md`.