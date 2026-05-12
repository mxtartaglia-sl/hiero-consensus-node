# PQ TLS — canonical follow-up documents

This directory holds the canonical record of the post-quantum TLS investigation for consensus gossip. Everything here represents validated findings only.

## Contents

| File | Purpose |
|---|---|
| [`proposal.md`](./proposal.md) | The proposal — what we want to do, why, and the open decisions for the team. |
| [`performance.md`](./performance.md) | Performance measurements. Methodology stated, all numbers re-measured on a single unified harness. |
| [`findings.md`](./findings.md) | Empirical findings and how each was verified. |
| [`experiments.md`](./experiments.md) | Catalog of debug variants in the `consensus-tls-debug` module — what each one runs and what it validates. |

## What's in `_archive/`

The previous iteration of these documents accumulated drift over its lifetime — multiple parallel RFCs, retracted measurements, inferred numbers later contradicted, stale IETF draft references. Rather than continue patching, the investigation was reset and the canonical documents above were rewritten from a fresh measurement matrix.

The archive is preserved for historical context. If a claim appears in an archived document but does not appear in one of the canonical documents above, it should be considered withdrawn. See [`_archive/ARCHIVE-NOTE.md`](./_archive/ARCHIVE-NOTE.md) for the specifics on why each was archived.

## Reading order

For decision-makers: start with `proposal.md`. It links to the supporting documents where needed.

For engineers about to size or implement: read `proposal.md` first, then `findings.md` for what's been verified, then `performance.md` for the numbers, then `experiments.md` for the harness.

For someone investigating a specific claim: check `findings.md` first — every claim is tagged with the experiment or source that verifies it.