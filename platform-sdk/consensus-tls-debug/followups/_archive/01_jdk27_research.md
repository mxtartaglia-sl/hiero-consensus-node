# Item 1: Java 27 / JEP 527 Deeper Investigation

**Question for the team**: does waiting for Java 27 give us the full post-quantum TLS story, or do we still need BCJSSE / custom code for authentication?

**Owner**: Maxi
**Est. effort**: 4–8 hours
**Status**: not started

---

## What we already know

### Confirmed

- **JEP 527** (Post-quantum hybrid key exchange) is integrated into JDK 27 and available in early-access builds from build 6 onwards. Source: [inside.java blog post](https://inside.java/2026/02/17/tls-post-quantum-hybrid-key-exchange/).
- JEP 527 adds three hybrid named groups:
  - `X25519MLKEM768` (enabled by default)
  - `SecP256r1MLKEM768`
  - `SecP384r1MLKEM1024`
- Delivered via SunJSSE, configurable through `jdk.tls.namedGroups` system property and `SSLParameters::setNamedGroups()`.
- JEP 527 scope is **key exchange only**. No authentication PQ.
- **JEP 496** (ML-KEM, JDK 24): ML-KEM primitives in SunJCE at JCA layer.
- **JEP 497** (ML-DSA, JDK 24): ML-DSA primitives in SunJCE at JCA layer.
- JDK 25 ships both 496 and 497 at JCA layer. Verified locally: `KeyPairGenerator.getInstance("ML-KEM-768")` and `Signature.getInstance("ML-DSA-65")` both work.
- **SunJSSE on JDK 25 does NOT wire ML-DSA or ML-KEM into the TLS handshake**:
  - `SSLParameters.setSignatureSchemes({"mldsa65", ...})` silently drops the PQ entries.
  - `SSLParameters.setNamedGroups({"X25519MLKEM768"})` silently drops it.
  - Confirmed by our `MtlsDebugPqJava` and `MtlsDebugMlKemJava` experiments.

### Gaps we need to close

- **No JEP filed for ML-DSA in TLS.** Need to confirm by searching openjdk.org/jeps.
- **SLH-DSA (SPHINCS+, FIPS 205)**: no known Java JEP. Need to check.
- **Falcon (FN-DSA)**: NIST chose it as the fourth PQ signature but FIPS 206 is still in draft. Need to check Java roadmap.
- **X-Wing** (a newer hybrid KEM using X25519 + ML-KEM-768 with a different construction): Is it being considered for Java?
- **Standards body status**: RFC 8446bis or follow-on RFCs for ML-DSA in TLS? IETF draft status?
- **JDK release timeline**: when does 27 go GA? What comes after?

---

## Research plan

### 1. JEP search

Search for any JEP that touches:
- TLS + ML-DSA / Dilithium
- TLS + SLH-DSA / SPHINCS+
- TLS + Falcon
- TLS + pure ML-KEM (not hybrid)

Sources:
- https://openjdk.org/jeps/0 (JEP index)
- https://bugs.openjdk.org search for PQ tags
- OpenJDK mailing lists: security-dev, tls-dev

### 2. OpenJDK security-dev mailing list activity

Search archives for:
- "ML-DSA"
- "Dilithium"
- "post-quantum signature"
- "authentication" + "post-quantum"

Look for discussion threads, JBS tickets, or proposal drafts.

### 3. JEP 527 scope clarification

Read JEP 527 text carefully. Does it mention authentication as out of scope for a specific reason? Any hints at follow-up JEPs?

### 4. IETF / NIST status

- RFC 9710 or follow-ons for ML-KEM in TLS
- draft-ietf-tls-mldsa for ML-DSA in TLS
- draft-ietf-tls-ecdhe-mlkem for hybrid groups (already implemented by BCJSSE)
- FIPS 204 (ML-DSA) and FIPS 206 (FN-DSA / Falcon) current status

### 5. JDK release schedule

- JDK 27 GA target date
- JDK 28, 29, 30 planning windows
- Any LTS implications (JDK 25 is the current LTS, JDK 29 or 33 would be the next)

### 6. Alternative JDK distributions

- **Amazon Corretto**: do they backport PQ features to older JDK lines? They maintain ACCP separately, so possibly.
- **Eclipse Temurin, Azul Zulu, GraalVM**: any PQ-specific patches?
- **Red Hat OpenJDK**: any early ML-DSA backports?

---

## Deliverable

A document with these sections:

1. **Summary verdict**: "Waiting for JDK N gives us X; it does NOT give us Y." One paragraph.
2. **JDK version matrix**: table showing which Java version brings which PQ feature in TLS.
3. **Key JEPs and their scope**: short description of each relevant JEP and what's in/out.
4. **IETF / standards status**: current draft status for PQ TLS extensions.
5. **Risks and unknowns**: timeline risk, dependency on external standardization, implementation risk.
6. **Recommendation**: given the findings, what's the recommended wait-or-ship decision.

---

## Open questions to answer

1. Is there ANY JEP in flight for ML-DSA in TLS? Even in the Draft stage?
2. When is JDK 27 GA expected? Is the early-access build stable enough to ship against?
3. Does Amazon Corretto backport TLS features? If yes, could we use Corretto 25 with JEP 527 backported?
4. How does the IETF treat ML-DSA-in-TLS vs ML-KEM-in-TLS? Are they being standardized together or separately?
5. What's the OpenJDK team's implicit priority order: more PQ signatures, faster PQ signatures, PQ authentication? This tells us what comes next after JEP 527.
6. Is there a Java FFI / Panama path to OpenSSL 3.5+ that would give us full PQ TLS independently of SunJSSE's roadmap?

---

## Verification procedure for a candidate JDK build

Once we download a candidate JDK (e.g., JDK 27 early access), we need to verify end-to-end whether SunJSSE accepts ML-DSA for authentication and ML-KEM for key exchange. The investigation's debug tool (`consensus-tls-debug` module) already has the variants needed.

### Quick verification (5 minutes)

Point the build at the candidate JDK and run the existing test variants. The test outcome tells us definitively whether the JDK has wired the PQ algorithms into TLS.

```bash
# 1. Point to the candidate JDK
export JAVA_HOME=/path/to/jdk-27-ea
export PATH=$JAVA_HOME/bin:$PATH
java -version   # confirm

# 2. Check what's registered at JCA level (both ML-DSA and ML-KEM primitives)
java -XshowSettings:security 2>&1 | grep -E "ML-DSA|ML-KEM" | head -20

# 3. Run the TLS-level tests
cd /Users/maxi/Hashgraph/code/1/hedera-services

# Test ML-KEM key exchange via SunJSSE
./gradlew :consensus-tls-debug:run --args="--mlkem-java --iterations=10 --warmup=3"

# Test ML-DSA authentication via SunJSSE
./gradlew :consensus-tls-debug:run --args="--pq-java --iterations=10 --warmup=3"
```

### How to interpret results

The handshake outcome tells you the answer at a high level:

- **Handshake succeeds** → SunJSSE supports the PQ algorithm in TLS.
- **Handshake fails with `handshake_failure`** → SunJSSE silently dropped the PQ entry from the ClientHello (same failure mode as JDK 25).

For a definitive check on what's happening under the hood, run with `--debug` and inspect the `signature_algorithms` extension of the ClientHello:

```bash
./gradlew :consensus-tls-debug:run --args="--pq-java --debug --iterations=1" 2>&1 \
    | grep -A2 "falc (13)"
```

**Expected output if ML-DSA IS supported** (the desired state):
```
"signature_algorithms (13)": {
  "signature schemes": [mldsa65, mldsa44, mldsa87, ecdsa_..., rsa_pss_...]
}
```

**Expected output if NOT supported** (same as JDK 25):
```
"signature_algorithms (13)": {
  "signature schemes": [ecdsa_..., ed25519, rsa_pss_...]
}
```

The presence of `mldsa*` entries in the ClientHello's `signature_algorithms` extension is the definitive signal that SunJSSE has wired ML-DSA into its TLS handshake code.

### Rigorous cross-check via OpenSSL interop (15 minutes)

If the quick test succeeds, confirm wire-format compatibility against an external peer that strictly requires ML-DSA. This catches "works with itself but isn't actually using ML-DSA correctly" edge cases.

Requires OpenSSL 3.6+ with ML-DSA support (`openssl list -signature-algorithms | grep ML-DSA`).

```bash
# Generate an ML-DSA cert pair using OpenSSL (no BC involved)
mkdir -p /tmp/mldsa-test && cd /tmp/mldsa-test
openssl req -x509 -newkey ML-DSA-65 -keyout ca.key -out ca.crt \
    -nodes -days 30 -subj "/CN=PQ-CA" \
    -addext "basicConstraints=critical,CA:TRUE"
openssl genpkey -algorithm ML-DSA-65 -out server.key
openssl req -new -key server.key -out server.csr -subj "/CN=server"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -days 30

# Start a server that REQUIRES ML-DSA signatures for CertificateVerify
openssl s_server -accept 19443 -www -tls1_3 \
    -cert server.crt -key server.key \
    -sigalgs mldsa65 \
    -quiet &

# Connect from the Java test harness
./gradlew :consensus-tls-debug:run \
    --args="--interop --host=localhost --port=19443 --ca=/tmp/mldsa-test/ca.crt --iterations=10 --warmup=3"
```

If the Java client handshakes successfully against this server, SunJSSE is genuinely doing ML-DSA over the wire — not silently falling back to something classical or failing the connection.

### Data to record

For each candidate JDK build, capture in the verdict section of this document:

1. **JDK build version**: full output of `java -version`.
2. **JCA-level support**: filtered output of `-XshowSettings:security` showing which ML-* algorithms are registered.
3. **signature_algorithms in ClientHello**: from `--debug` output, verbatim. Definitive evidence of TLS-level support or absence.
4. **ML-KEM handshake result**: success / fail / fallback to classical.
5. **ML-DSA handshake result**: success / fail / fallback to classical.
6. **OpenSSL interop result** (if ML-DSA passed the quick test): success / fail.

If all six say "yes, works," the JDK is verified to support PQ TLS end-to-end.

### Static source inspection (fastest preflight check)

Before even running the benchmark, check the JDK's source for PQ-related enum entries. SunJSSE's TLS-level support is gated by two classes in `src.zip`:

- `java.base/sun/security/ssl/SignatureScheme.java` — enum of TLS 1.3 signature schemes. Must contain `MLDSA*` entries for ML-DSA authentication to work.
- `java.base/sun/security/ssl/NamedGroup.java` — enum of named groups. Must contain `*MLKEM*` entries for ML-KEM key exchange to work.

If these enums don't have the PQ entries, SunJSSE will silently filter out any `mldsa*` / `X25519MLKEM768` values passed via `SSLParameters.setSignatureSchemes` / `setNamedGroups`. This is the root cause of the JDK 25 silent-drop behavior.

**One-liner to check a JDK build**:

```bash
check_pq() {
    local jdk=$1
    echo "=== $jdk ==="
    echo -n "SignatureScheme enum PQ entries: "
    unzip -p "$jdk/lib/src.zip" java.base/sun/security/ssl/SignatureScheme.java 2>/dev/null \
        | grep -cE "MLDSA|SLHDSA|FALCON"
    echo -n "NamedGroup enum PQ entries: "
    unzip -p "$jdk/lib/src.zip" java.base/sun/security/ssl/NamedGroup.java 2>/dev/null \
        | grep -cE "MLKEM|KYBER"
}

check_pq ~/.sdkman/candidates/java/25.0.2-tem
check_pq /path/to/jdk-27-ea
```

Expected on JDK 25: both counts are 0 (no PQ).
Expected on JDK 27 per JEP 527: `NamedGroup` count > 0 (ML-KEM added), `SignatureScheme` count = 0 (no ML-DSA JEP filed).

If the counts match expectations, the verification proceeds to the runtime benchmark. If they don't match (e.g., NamedGroup has MLKEM entries on JDK 25), something has changed in the build and further investigation is warranted.

### Tentative verdict (based on standards research)

From JDK 27's own standard-names documentation and IANA's TLS parameters registry:

- **IANA has assigned code points** for `mldsa44 (0x0904)`, `mldsa65 (0x0905)`, `mldsa87 (0x0906)` under `tls-signaturescheme`.
- The IANA entry references `draft-ietf-tls-mldsa-00` — the earliest revision of the IETF draft.
- JDK 27's standard names doc does not list these entries (only classical schemes). If they were implemented, they'd be listed there.
- This strongly suggests **JDK 27 will NOT include ML-DSA in TLS** because the underlying IETF draft is not yet ratified as an RFC.

Standards process timeline:
- `draft-ietf-tls-mldsa` is at draft-00. Typical IETF draft → RFC process takes 1-3 years with multiple revisions.
- OpenJDK's historical pattern: ships TLS signature schemes only after RFC publication.
- JEP proposal and implementation cycle adds another 6-12 months after RFC.

**Realistic estimate: ML-DSA-in-TLS via SunJSSE is 2-3 years away.**

### Why OpenSSL and BouncyCastle have it already

OpenSSL and BCJSSE implement pre-standard drafts ahead of OpenJDK because they operate under different engineering philosophies:

- **OpenJDK / SunJSSE**: conservative. Signature schemes enter SunJSSE only after the wire format is finalized via RFC. Avoids risk of future-incompatible deployments. Cost: years of delay.
- **BouncyCastle**: research-oriented. Tracks IETF drafts and NIST publications closely. Ships experimental code points with comments like `@deprecated Experimental API (unstable)`. Willing to break compat across versions when drafts change wire formats. BC ships `mldsa65(0x0905)` based on `draft-ietf-tls-mldsa-00`.
- **OpenSSL**: pragmatic. Implements what major users (Cloudflare, Google, AWS) are already deploying. Coordinates with BoringSSL / AWS-LC on wire formats to maintain interop. First-mover by design.

Why this isn't reckless:
1. **Wire code points are usually stable early** — IETF assigns code points once the algorithm is chosen. `mldsa65 = 0x0905` is unlikely to change.
2. **Industry pre-consensus** — Cloudflare, Google, AWS coordinate via IETF TLS WG meetings. By the time a draft is referenced in IANA's registry, major implementers have agreed.
3. **Fallback is safe** — TLS negotiation handles unknown schemes gracefully; bad ML-DSA fails to connect but doesn't corrupt data.

### Implications for our decision

Shipping PQ authentication via BCJSSE today means accepting:

1. **Interop risk during draft evolution**: if `draft-ietf-tls-mldsa-00` becomes `draft-01` with wire changes, our fleet may fragment until upgraded.
2. **BCJSSE version churn**: BC updates may require coordinated rollouts.
3. **Standards-tracking burden**: someone needs to watch the IETF draft.

Alternative: defer PQ authentication until the RFC lands and SunJSSE ships it. Stable target, but ~2-3 years of classical authentication in the interim.

**This is a real trade-off the spec document (item 3) needs to call out explicitly.** Not just "ship now or wait for OpenJDK" but "first-mover with draft-churn risk, or stable-target with extended wait."

### Falcon / FN-DSA status

Falcon is the other NIST-selected PQ signature algorithm alongside ML-DSA. Useful to record its status so we don't mistakenly plan around it as an alternative.

- **NIST FIPS 206 (FN-DSA)** is still a draft. No ratified standard.
- **IETF TLS**: no draft exists yet for Falcon in TLS. By contrast, `draft-ietf-tls-mldsa` has reached draft-00.
- **IANA code points**: not assigned for Falcon/FN-DSA in the TLS signature scheme registry.
- **BouncyCastle**: supports Falcon at JCA level but explicitly as **experimental** — maintainer confirms "it should be treated as experimental still" and that algorithm modifications are expected when the FN-DSA spec finalizes. Source: [bc-java discussion #1898](https://github.com/bcgit/bc-java/discussions/1898).
- **BCJSSE TLS**: not documented.
- **OpenSSL**: no Falcon support visible in 3.6.
- **ACCP**: not present.

**Falcon is at least a year behind ML-DSA in standardization**. Not a candidate for active planning.

### Evidence links

- JDK 27 standard names: https://download.java.net/java/early_access/jdk27/docs/specs/security/standard-names.html
- IANA TLS signature scheme registry: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme
- IETF draft for ML-DSA in TLS: https://datatracker.ietf.org/doc/html/draft-ietf-tls-mldsa-00
- JEP 527: https://openjdk.org/jeps/527
- BouncyCastle Falcon discussion: https://github.com/bcgit/bc-java/discussions/1898

### Expected coverage matrix (to be filled in as we test)

| JDK build | ML-KEM at JCA | ML-KEM in TLS | ML-DSA at JCA | ML-DSA in TLS | OpenSSL interop |
|---|---|---|---|---|---|
| JDK 25 (Temurin 25.0.2) | ✓ | ✗ (silent drop) | ✓ | ✗ (silent drop) | n/a |
| JDK 27 EA build X | ? | ? (expect ✓ per JEP 527) | ? | ? (no JEP filed) | ? |
| JDK 28 EA (if released) | ? | ? | ? | ? | ? |
| Corretto 25 | ? | ? | ? | ? | ? |

Fill in as each build is tested.