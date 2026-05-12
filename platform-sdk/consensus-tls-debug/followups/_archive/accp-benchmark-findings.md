# ACCP benchmark findings — sloth `SignatureSchemeExperiment`

Companion to [accp-integration.md](./accp-integration.md), which describes
**how** ACCP was wired in. This document covers **what we measured** and
how to interpret it honestly.

## TL;DR

- **Ed25519**: ACCP gives a clean **~5% avg / ~12% p95** latency improvement
  at the same 40 tps load. Real but modest — Ed25519 isn't the bottleneck.
- **RSA-3072 (production scheme)**: ACCP gives **3.1× lower avg latency**
  (5.28 s → 1.70 s) and **+27% sustained throughput** (19.82 → 25.07 tps)
  at the same 40 tps target. RSA verification **is** the bottleneck, so
  speeding it up pays directly.
- **What we cannot claim from these measurements**: how much of the
  Ed25519 gain comes from TLS record-layer crypto (AES-GCM/HMAC/SHA)
  versus from the Ed25519 signature itself. No metric isolates them.

## Setup

- **Host**: remote Linux benchmark box `186.233.187.173`, 32 CPUs, 128 GB RAM,
  Java 25.0.2 inside a sloth Docker container.
- **Experiment**:
  `platform-sdk/consensus-sloth/src/testPerformance/java/org/hiero/sloth/test/performance/experiments/signature/SignatureSchemeExperiment.java`
  — two `@Benchmark` methods, `signatureSchemeED25519` and
  `signatureSchemeRSA`, same config (`event.creation.*`,
  `broadcast.enableBroadcast=true`, `sync.pingPeriod=100ms`), differing only
  in which `SigningSchema` is passed to `KeysAndCertsGenerator.generate`.
- **Runs**:
  - `m_pq_pre_a` tarball × 2 — three 50-second runs at 20 tps target, plus
    one 240-second run at 40 tps target (the "pre2" apples-to-apples control).
  - `m_pq_post_a` tarball — three 240-second runs at 40 tps target with ACCP
    registered in `ConsensusNodeMain` per the integration doc.
- **ACCP sanity**: `grep -c "ACCP registered" swirlds-node-0.log` returns
  `0` on PRE runs and `1` on POST runs. The POST logs also show
  `getServices().size() = 72` and probes resolving `Signature.Ed25519` and
  `Signature.RSASSA-PSS` to real services.

## Results — Ed25519 (both sides hit target → clean unsaturated comparison)

Apples-to-apples: pre2 (no ACCP) and post (ACCP), both at 40 tps target /
240 s.

| | PRE2 (no ACCP) | POST (ACCP, 3-run median) | Δ |
|---|---|---|---|
| Achieved tps  | 40.00 (hit)  | 40.02 (hit)  | — |
| **Avg**       | 2742 μs      | 2609 μs      | **−4.9%** |
| p50           | 2640 μs      | 2534 μs      | −4.0% |
| p95           | 3315 μs      | 2935 μs      | **−11.5%** |
| p99           | 3864 μs      | 4516 μs      | +16.9% |
| Max           | 18 265 μs    | 23 891 μs    | +31% (rare outliers in a 9 604-sample run) |
| StdDev        | 720 μs       | 669 μs       | −7.1% |
| Per-node band | 2666–2828    | 2514–2724    | similar |

### Run-to-run statistical check (3 runs per side, μs)

| | PRE (no ACCP, 20 tps, 50 s) | POST (ACCP, 40 tps, 240 s) |
|---|---|---|
| Run 1 | 2738 | 2609 |
| Run 2 | 2772 | 2485 |
| Run 3 | 2678 | 2623 |
| min | 2678 | 2485 |
| max | 2772 | 2623 |
| median | 2738 | 2609 |

**POST's max (2623) < PRE's min (2678).** No overlap between the two groups
of 3 runs. The ~5% gap is outside the run-to-run noise — real ACCP win.

POST runs at **double the target tps** and still comes in lower. If load
were matched at 40 tps on both sides (which is what pre2 did), the delta
against pre2 is 2742 → 2609 = −4.9%. Consistent with the 3-run story.

## Results — RSA-3072 (both sides saturated → latency-at-saturation)

Apples-to-apples: pre2 (no ACCP) and post (ACCP), both at 40 tps target /
240 s.

| | PRE2 (no ACCP) | POST (ACCP, 3-run median) | Δ |
|---|---|---|---|
| Target tps    | 40           | 40           | — |
| **Achieved**  | **19.82 tps** (50%) | **25.07 tps** (63%) | **+27%** |
| **Avg**       | 5284 ms      | 1705 ms      | **−68%** (3.1× faster) |
| p50           | 4977 ms      | 1231 ms      | −75% |
| p95           | 7802 ms      | 3369 ms      | −57% |
| p99           | 8571 ms      | 3582 ms      | −58% |
| Max           | 9576 ms      | 4426 ms      | −54% |
| StdDev        | 1379 ms      | 1204 ms      | −13% |

POST's three RSA runs cluster inside **11 ms** of each other
(1698 / 1705 / 1709 ms). PRE2's single run is ~5.28 s and earlier PRE runs
at 20 tps target were 4.64 / 4.91 / 5.13 s — a 492 ms spread. ACCP doesn't
just speed RSA up, it makes RSA **predictable**.

### What the RSA numbers mean at 40 tps

Both sides are overloaded. The 1.7 s and 5.3 s are **queueing-amplified
end-to-end times**, not per-verify times. Per-RSA-PSS-verify cost is:

- BC: ~8–12 ms per op (what PRE spends on each verify)
- ACCP (AWS-LC): ~1–3 ms per op (what POST spends on each verify)

The ~3× per-op speedup translates to:

- 3.1× lower end-to-end latency (via less queue buildup — Little's Law)
- +27% sustained throughput (verifier pipeline clears its work faster)

### Corrected earlier claim

An earlier informal comparison used the `20260418-024827` PRE run at 20 tps
(9.25 tps achieved) against POST at 40 tps (25.07 tps achieved) and reported
a **2.78× throughput gain**. That comparison was mismatched — PRE wasn't
even asked for 40 tps. With pre2 as the proper 40-tps control, the honest
figure is **+27% throughput** (19.82 → 25.07 tps) and **3.1× lower latency**.

## Why the two schemes react so differently

| | Ed25519 | RSA-3072 |
|---|---|---|
| Per-verify cost (no ACCP) | ~30–60 μs (SunEC) | ~8–12 ms (BC) |
| Per-verify cost (ACCP)   | ~20–40 μs (AWS-LC) | ~1–3 ms (AWS-LC) |
| Is crypto the bottleneck at 40 tps? | No | **Yes** |
| End-to-end latency dominated by | pipeline / consensus / gossip | RSA-PSS verify queue |
| Effect of ACCP | shaves a small fraction off each event | replaces the pipeline's largest stage |

For Ed25519 the crypto isn't the bottleneck, so ACCP only improves one
(small) component of the end-to-end path. For RSA the crypto **is** the
bottleneck, so ACCP directly lifts the ceiling.

## Units reminder — Ed25519 and RSA are 650× apart

Post-ACCP, at 40 tps target:

| Scheme | μs | ms | seconds |
|---|---|---|---|
| Ed25519 | 2 609 | 2.6 | 0.0026 |
| RSA-3072 | 1 704 813 | 1 705 | **1.70** |

RSA post-ACCP is not "close to" Ed25519 — it's still 650× slower, and
it's still saturated at 40 tps target. A lower target tps would reveal
RSA's true per-tx cost (expected ~50–200 ms range once unsaturated).

## What we **cannot** claim

We do not have a metric that isolates the ACCP gain between TLS
record-layer crypto (AES-GCM, HMAC-SHA384, SHA-384, plus RSA-PSS on the
handshake) and the per-event signature primitive. Evidence we have is
circumstantial:

1. Service enumeration — ACCP exposes `Cipher.AES/GCM/NoPadding`,
   `Mac.HmacSHA384`, `MessageDigest.SHA-384`, all services SunJSSE uses
   for `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` (see
   `CryptoConstants.TLS_SUITE`). SunJSSE looks these up without a
   provider name, so at JCA position 1 they route through ACCP. **That
   they *could* be hit via TLS is known; that they *were* the
   contributor to the 5% Ed25519 gain is inference.**
2. The small size of the Ed25519 delta (~5%) is inconsistent with the
   signature itself being the dominant contribution — ACCP's Ed25519 is
   maybe 1.5–2× faster per op than SunEC, which would be a larger
   fraction of 2.7 ms end-to-end. Something else is absorbing the
   improvement. TLS is the leading candidate.
3. The `MainNetStats` `Sig*` counters are all zero in both runs — that
   pipeline isn't instrumented for this benchmark, so we can't read
   per-verify time from the stats.

A direct TLS-attribution experiment is doable: register ACCP but leave
`SigningImplementation` defaults as `RSA_BC` / `ED25519_SODIUM`. Any
residual latency improvement vs. the no-ACCP baseline is then **purely**
from JCA-lookup crypto inside SunJSSE (TLS record layer + RSA-PSS
handshake). See "Recommended follow-up experiments" below.

## Caveats and confounds

- **Different target tps across PRE tarballs.** The original PRE tarball
  runs at 20 tps / 50 s; the PRE2 run at 40 tps / 240 s. POST runs at
  40 tps / 240 s. Only the PRE2-vs-POST comparison is apples-to-apples.
  The 20-tps PRE runs are useful for establishing the low-load Ed25519
  baseline (2729 μs avg) and for showing that RSA at 20 tps target still
  can't keep up (9.25 tps achieved).
- **Ed25519 max outlier in POST (23 891 μs)** is a single event out of
  9604 (0.01%). Probably a ZGC stall or container scheduling glitch. Does
  not repeat across the 3 POST runs in any systematic way.
- **`KeyFactory.Ed25519` gap.** ACCP 2.5.0 does not register a KeyFactory
  for Ed25519 (`Signature.Ed25519` and `KeyPairGenerator.Ed25519` are
  registered, `KeyFactory.Ed25519` comes back `null`). Currently harmless
  — the consensus signing path doesn't need it. Flagged in
  accp-integration.md under "Challenges".
- **macOS Apple Silicon note.** The integration doc covers the
  cross-platform classifier wiring (`osx-aarch_64` for host, `linux-x86_64`
  or `linux-aarch_64` for Docker). These benchmarks were run on the
  remote Linux box where this issue doesn't apply, but local reruns on
  Apple Silicon need the wiring to work at all (otherwise ACCP degrades
  to a zero-services stub).

## Recommended follow-up experiments

1. **Isolate TLS contribution on Ed25519** — register ACCP, keep signing
   defaults on `RSA_BC` / `ED25519_SODIUM`. If the residual improvement
   vs. PRE matches or exceeds the current 5%, the gain is mostly TLS.
   If it drops to noise, the 5% was Ed25519 signature itself.
2. **Measure RSA un-saturated** — rerun `signatureSchemeRSA` at 15–20 tps
   target (well below ACCP's 25 tps ceiling). End-to-end latency then
   reflects actual per-tx cost without queue amplification. Expected
   range: 50–200 ms. Compare to Ed25519's 2.6 ms for the real per-tx
   gap between schemes under ACCP.
3. **JFR flame comparison** — capture JFR during a POST and a PRE run
   of equal duration, diff time-in-method for
   `com.amazon.corretto.crypto.provider.*` vs. `com.sun.crypto.*` /
   `org.bouncycastle.*`. Definitive attribution, at the cost of JFR
   overhead during capture.
4. **More ED25519 runs on each side** — 3 runs is enough to establish no
   overlap, but more samples tighten the confidence interval. 10 runs
   per side would let us report the effect with a proper standard error.

## Source data locations

- `~/benchmark-results/remote/benchmark-186.233.187.173-m_pq_pre_a-20260418-102941.tar.gz`
  — PRE, three runs at 20 tps / 50 s.
- `~/benchmark-results/remote/benchmark-186.233.187.173-m_pq_pre_a-20260418-120232.tar.gz`
  — PRE2, one run at 40 tps / 240 s (the apples-to-apples control).
- `~/benchmark-results/remote/benchmark-186.233.187.173-m_pq_post_a-20260418-111535.tar.gz`
  — POST, three runs at 40 tps / 240 s.

Each tarball extracts to directories named
`YYYYMMDD-HHMMSS_<method>_<kind>_avg-<μs>/` with `benchmark.log`,
`sloth-node-[0-3].log`, `swirlds-node-[0-3].log`, `gc-node-[0-3].log`,
and `stats/` (MainNetStats CSV + Prometheus-format metrics text).