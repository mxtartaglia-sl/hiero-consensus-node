# IANA TLS SignatureScheme Registry — Summary

Snapshot of the IANA TLS SignatureScheme registry relevant to our PQ TLS planning. Fetched from [the IANA CSV source](https://www.iana.org/assignments/tls-parameters/tls-signaturescheme.csv) on 2026-04-16.

The registry governs which signature scheme identifiers are allowed on the TLS 1.3 wire in the `signature_algorithms` extension and `CertificateVerify` message. Every wire code point used by any TLS stack must appear here.

## Status glossary

- **Recommended = Y**: the IETF TLS WG recommends this scheme for use. Supported in mainstream stacks (SunJSSE, OpenSSL, BCJSSE).
- **Recommended = N**: defined, but either legacy/deprecated, niche (national crypto), experimental, or pre-standard.
- **Reference = RFC-\***: ratified or in-progress standards-track RFC.
- **Reference = draft-\***: IETF Internet-Draft. Wire format subject to change.

## RFC-backed, recommended (production-ready)

These are the schemes every mainstream TLS 1.3 stack supports. All reference `RFC-ietf-tls-rfc8446bis-13` (the in-flight revision of RFC 8446).

| Code | Name | Family |
|---|---|---|
| 0x0401 | rsa_pkcs1_sha256 | RSA PKCS#1 v1.5 (cert chains only in TLS 1.3) |
| 0x0501 | rsa_pkcs1_sha384 | RSA PKCS#1 v1.5 (cert chains only) |
| 0x0601 | rsa_pkcs1_sha512 | RSA PKCS#1 v1.5 (cert chains only) |
| 0x0403 | ecdsa_secp256r1_sha256 | ECDSA P-256 |
| 0x0503 | ecdsa_secp384r1_sha384 | ECDSA P-384 |
| 0x0603 | ecdsa_secp521r1_sha512 | ECDSA P-521 |
| 0x0804 | rsa_pss_rsae_sha256 | RSA-PSS with RSASSA-PSS key |
| 0x0805 | rsa_pss_rsae_sha384 | RSA-PSS with RSASSA-PSS key |
| 0x0806 | rsa_pss_rsae_sha512 | RSA-PSS with RSASSA-PSS key |
| 0x0809 | rsa_pss_pss_sha256 | RSA-PSS with PSS-only key |
| 0x080A | rsa_pss_pss_sha384 | RSA-PSS with PSS-only key |
| 0x080B | rsa_pss_pss_sha512 | RSA-PSS with PSS-only key |
| 0x0807 | ed25519 | EdDSA over Curve25519 |
| 0x0808 | ed448 | EdDSA over Curve448 |

## Draft-stage post-quantum (the critical section for our investigation)

This is what matters for the PQ question. **All PQ signatures in the registry reference Internet Drafts, not RFCs.** Recommended = N across the board.

### ML-DSA (formerly CRYSTALS-Dilithium, NIST FIPS 204)

| Code | Name | Reference |
|---|---|---|
| 0x0904 | mldsa44 | `draft-ietf-tls-mldsa-00` |
| 0x0905 | mldsa65 | `draft-ietf-tls-mldsa-00` |
| 0x0906 | mldsa87 | `draft-ietf-tls-mldsa-00` |

- **Status**: draft-00 (earliest IETF revision; wire format subject to change)
- **Implementations**: BouncyCastle (treats as stable), OpenSSL 3.6+, ACCP 2.5+
- **SunJSSE**: NOT implemented on JDK 25 or 27

### SLH-DSA (formerly SPHINCS+, NIST FIPS 205)

| Code | Name | Reference |
|---|---|---|
| 0x0911 | slhdsa_sha2_128s | `draft-reddy-tls-slhdsa-01` |
| 0x0912 | slhdsa_sha2_128f | `draft-reddy-tls-slhdsa-01` |
| 0x0913 | slhdsa_sha2_192s | `draft-reddy-tls-slhdsa-01` |
| 0x0914 | slhdsa_sha2_192f | `draft-reddy-tls-slhdsa-01` |
| 0x0915 | slhdsa_sha2_256s | `draft-reddy-tls-slhdsa-01` |
| 0x0916 | slhdsa_sha2_256f | `draft-reddy-tls-slhdsa-01` |
| 0x0917 | slhdsa_shake_128s | `draft-reddy-tls-slhdsa-01` |
| 0x0918 | slhdsa_shake_128f | `draft-reddy-tls-slhdsa-01` |
| 0x0919 | slhdsa_shake_192s | `draft-reddy-tls-slhdsa-01` |
| 0x091A | slhdsa_shake_192f | `draft-reddy-tls-slhdsa-01` |
| 0x091B | slhdsa_shake_256s | `draft-reddy-tls-slhdsa-01` |
| 0x091C | slhdsa_shake_256f | `draft-reddy-tls-slhdsa-01` |

- **Status**: draft-01 (individual submission, not yet WG-adopted)
- **Implementations**: BouncyCastle (under slhdsa_* names; `@Deprecated DRAFT_*` aliases)
- Draft is an individual submission (`draft-reddy-*`, not `draft-ietf-*`), which is earlier in the standardization pipeline than ML-DSA's `draft-ietf-tls-mldsa-00`.

### Falcon / FN-DSA (NIST FIPS 206 — still draft)

**Not in the IANA registry.** Falcon has no wire code points assigned. No TLS draft exists. Confirmed by separate research: [bc-java discussion #1898](https://github.com/bcgit/bc-java/discussions/1898) — BouncyCastle's own Falcon support is flagged as experimental pending FN-DSA's final form, and it's not wired into TLS.

### Observations on the draft-stage section

- **Only three PQ signature families have code points assigned**: ML-DSA (Dilithium), SLH-DSA (SPHINCS+), and none yet for Falcon/FN-DSA.
- **All are `Recommended = N`** — the IETF has not endorsed them for production use yet.
- **None have RFC references** — all reference internet-drafts, meaning wire formats are subject to change.
- **The ML-DSA draft is the most mature** (WG-adopted `draft-ietf-*`), followed by SLH-DSA (individual submission `draft-reddy-*`), with Falcon nowhere.

## Legacy / deprecated / non-recommended

### Legacy SHA-1 (deprecated but kept for TLS 1.2 compatibility)

| Code | Name | Note |
|---|---|---|
| 0x0201 | rsa_pkcs1_sha1 | Recommended = N, co-referenced RFC 9155 |
| 0x0203 | ecdsa_sha1 | Recommended = N, co-referenced RFC 9155 |

### PKCS#1 v1.5 "legacy" variants (transitional)

| Code | Name | Reference |
|---|---|---|
| 0x0420 | rsa_pkcs1_sha256_legacy | `draft-ietf-tls-tls13-pkcs1-07` |
| 0x0520 | rsa_pkcs1_sha384_legacy | `draft-ietf-tls-tls13-pkcs1-07` |
| 0x0620 | rsa_pkcs1_sha512_legacy | `draft-ietf-tls-tls13-pkcs1-07` |

Draft-only, for backward compat with environments that can't migrate to RSA-PSS.

### Brainpool curves (RFC 8734, Recommended = N)

| Code | Name |
|---|---|
| 0x081A | ecdsa_brainpoolP256r1tls13_sha256 |
| 0x081B | ecdsa_brainpoolP384r1tls13_sha384 |
| 0x081C | ecdsa_brainpoolP512r1tls13_sha512 |

### Identity-Based Crypto (draft-only)

| Code | Name | Reference |
|---|---|---|
| 0x0704 | eccsi_sha256 | `draft-wang-tls-raw-public-key-with-ibc-02` |
| 0x0705 | iso_ibs1 | same |
| 0x0706 | iso_ibs2 | same |
| 0x0707 | iso_chinese_ibs | same |

### National/regional schemes

| Code | Name | Reference |
|---|---|---|
| 0x0708 | sm2sig_sm3 | RFC 8998 (Chinese SM2) |
| 0x0709–0x070F | gostr34102012_* | RFC 9367 (Russian GOST) |

Not relevant for our planning — national crypto suites for regulatory environments.

## Implications for our planning

### 1. "Recommended = N" is the norm for PQ

Every post-quantum signature in the registry is currently `Recommended = N`. This is not a safety judgment on the algorithms themselves — it reflects that the IETF TLS WG hasn't ratified the wire formats yet. Any stack shipping ML-DSA in TLS today (BC, OpenSSL) is operating in pre-standard territory.

### 2. OpenJDK's inclusion criterion is RFC maturity

As discussed in `01_jdk27_research.md`, OpenJDK's history suggests they include signature schemes in SunJSSE only after the wire format is finalized via RFC. With only `draft-ietf-tls-mldsa-00` available, ML-DSA is unlikely to appear in SunJSSE until the RFC publishes — realistically 2026-2027 minimum.

### 3. ML-DSA is the only viable near-term PQ signature

- **Falcon**: no code points, no TLS draft. Unavailable.
- **SLH-DSA**: code points assigned but from an individual draft. Less mature than ML-DSA. Slow-ish signatures (designed for size, not speed) — would hurt handshake latency.
- **ML-DSA**: code points assigned, WG draft, implementations in BC and OpenSSL. Mature enough for first-mover deployments.

**If we ship PQ authentication in the near term, it will be ML-DSA.** There's no meaningful alternative.

### 4. Draft revision churn is a real risk

The `-00` suffix on `draft-ietf-tls-mldsa-00` means this is the first revision of the working group draft. Subsequent revisions are highly likely, and while wire code points usually persist across revisions, other details (hash modes, salting, extension structure) can change. Our BCJSSE-based deployment must plan for periodic updates as the draft progresses.

### 5. SLH-DSA is worth tracking but not planning around

If ML-DSA deployment hits issues (performance, security concerns, cryptanalytic weaknesses), SLH-DSA would be the fallback. It's in the registry, BouncyCastle has it, but it's one maturity level behind and has larger signatures. Keep as a contingency, not a primary path.

### 6. Registry evolution to watch

Things that would change our planning if they appeared:

- **`draft-ietf-tls-mldsa-01` or `-02`**: update BC, check for wire changes.
- **`RFC-ietf-tls-mldsa`**: ML-DSA becomes RFC-track. OpenJDK clock starts for inclusion.
- **New PQ signature schemes appearing**: unlikely in the next year.
- **`Recommended = Y` flip for mldsa*`**: IETF WG endorsement, strong signal to deploy.

## Evidence

- IANA CSV source: https://www.iana.org/assignments/tls-parameters/tls-signaturescheme.csv
- ML-DSA draft: https://datatracker.ietf.org/doc/html/draft-ietf-tls-mldsa-00
- SLH-DSA draft: https://datatracker.ietf.org/doc/html/draft-reddy-tls-slhdsa-01
- RFC 8446bis (in-flight TLS 1.3 revision): https://datatracker.ietf.org/doc/html/draft-ietf-tls-rfc8446bis