# ACCP integration in the consensus-sloth benchmark

## Goal

Use the Amazon Corretto Crypto Provider (ACCP) — backed by AWS-LC native code —
to accelerate the cryptographic operations exercised by the
`combinedAllOptimizations` benchmark in `consensus-sloth`, and measure the
end-to-end effect on consensus latency.

Two targets must work simultaneously:

- The **gradle test-worker JVM** running on the developer's host (macOS arm64
  / linux x86_64) — this orchestrates the benchmark and generates keys.
- The **Docker child JVM** running `ConsensusNodeMain` inside the sloth
  container — this is the actual consensus node and where the per-event
  crypto cost lives.

## Final result

ACCP is now wired in correctly. On the Linux benchmark host, with a clean
apples-to-apples pair of runs (`~/benchmark-results-linux-pq/`):

| Metric                     | main (no ACCP) | pq (ACCP) | Δ        |
|----------------------------|----------------|-----------|----------|
| Avg consensus latency      | 3195 μs        | 2719 μs   | **−15%** |
| p50                        | 3143 μs        | 2659 μs   | −15%     |
| p95                        | 3879 μs        | 3015 μs   | **−22%** |
| p99                        | 4526 μs        | 5139 μs   | +14%     |
| `bytes_per_sec_sent`       | 1.45 MB/s      | 1.72 MB/s | **+18%** |
| ZGC stop-the-world (total) | 2.82 ms        | 2.53 ms   | ~equal   |

Headline: **−15% average latency, −22% p95**, paid for by ~3× more
short-lived allocations (more `Allocation Rate` ZGC triggers, peak heap
80% vs 45%) — but ZGC absorbs the churn with no measurable pause cost.

## Where the win lives

ACCP exposes 72 JCA services in this build (confirmed at runtime). The hot
contributors:

- **TLS record-layer crypto** — `Cipher.AES/GCM/NoPadding`,
  `Mac.HmacSHA384`, `MessageDigest.SHA-384`. SunJSSE finds these via
  position-1 JCA lookup, so every gossip message benefits without any
  TLS-side code change.
- **Event signing/verification** — `Signature.Ed25519` (registered as
  `EvpSignatureRaw$Ed25519`).
- **TLS handshake** — `Signature.RSASSA-PSS` for cert verification per peer
  connection.

## Process — what we changed, in order

1. **Added `RSA_ACCP` and `ED25519_ACCP`** values to
   `platform-sdk/consensus-utility/src/main/java/org/hiero/consensus/crypto/SigningImplementation.java`.
2. **Added `setDefaultImplementation(...)`** to `SigningFactory.java` so a
   bootstrap step can flip defaults at startup.
3. **Added a fail-loud guard** in `SigningFactory` (`used` flag) — any
   default-reading `createSigner`/`createVerifier` flips it to `true`, after
   which `setDefaultImplementation` throws. Prevents stale-default reads.
4. **Declared ACCP in the dependency catalog** —
   `hiero-dependency-versions/build.gradle.kts` got
   `api("software.amazon.cryptools:AmazonCorrettoCryptoProvider:2.5.0") { because("com.amazon.corretto.crypto.provider") }`.
5. **Wired two classifier configurations** in
   `platform-sdk/consensus-sloth/build.gradle.kts`:
   - `testFixturesRuntimeOnly` with the **host-detected classifier** for the
     gradle test worker JVM.
   - `accpDockerBundle` (a separate resolvable configuration) with the
     **target-arch classifier** for the Docker bundle, auto-detected from
     host arch and overridable via `-PaccpDockerClassifier=…`.
6. **Modified `copyDockerizedApp`** to exclude any ACCP host classifier from
   `lib/` and substitute in `accpDockerBundle` instead — the test JVM gets
   one classifier, the container gets a possibly-different one, and the
   module path of each is conflict-free.
7. **Registered ACCP in `ConsensusNodeMain.main()`** (the child JVM that
   actually does the consensus work), via reflection so the call is a
   no-op when ACCP is absent. Added diagnostic logging that prints
   `getServices().size()`, every service, and direct probes for
   `Signature.Ed25519` / `RSASSA-PSS` etc.

## Challenges hit and how each was solved

### 1. ACCP was being registered in the wrong JVM

The first attempt registered ACCP in
`platform-sdk/consensus-sloth/src/testFixtures/.../docker/DockerMain.java`
— but `DockerMain` is just a gRPC orchestrator (`DockerManager.java:100-132`
forks a brand-new JVM via `ProcessBuilder` whose main class is
`ConsensusNodeMain`). The forked child JVM has its own JCA state.

**Symptom:** ACCP loader warning appeared in `benchmark.log` (test JVM)
but never in the container logs. The override never reached the child.

**Fix:** moved `registerAccpIfAvailable()` to `ConsensusNodeMain.main()`,
the actual consensus entry point.

### 2. The "ACCP is slower" benchmarks were a confound

Earlier runs showed pq (3346–3378 μs) slower than main (2738 μs). The same
commit that wired ACCP also commented out
`modules.eventIntake = org.hiero.consensus.event.intake.concurrent` in
`CombinedOptimizationsExperiment.java`. Turning ACCP on coincided with
turning off the concurrent-intake optimization — the regression was the
intake change, not ACCP.

Compounded by issue (1): ACCP wasn't even doing anything in the child JVM
at the time.

**Fix:** kept the intake config consistent across the comparison runs;
re-ran with ACCP correctly registered.

### 3. ACCP's base jar is empty (261 bytes)

ACCP 2.5.0's no-classifier artifact contains only `META-INF/MANIFEST.MF`
with `Manifest-Version: 1.0` — nothing else. All Java classes, native
libraries, and `module-info.class` live in the platform-classifier jars
(`linux-x86_64`, `linux-aarch_64`, `osx-aarch_64`, `osx-x86_64`).

**Symptom:** the JPMS transform failed with "Not a module and no mapping
defined: AmazonCorrettoCryptoProvider-2.5.0.jar".

**Fix:** stopped pulling in the base jar — only depend on the classifier
jars, each of which is a complete self-contained JPMS module.

### 4. The hiero strict JPMS conventions

`hiero-gradle-conventions` 0.7.6 sets
`extraJavaModuleInfo.failOnAutomaticModules = true`. Every jar must be a
real JPMS module (`module-info.class`) or be explicitly mapped — both
the base ACCP jar and an attempted `module(…)` declaration tripped this.

**Fix:** since each classifier jar already contains its own
`module-info.class` declaring `com.amazon.corretto.crypto.provider`, no
`extraJavaModuleInfo` mapping is needed at all once the empty base jar is
out of the picture.

### 5. Multiple classifiers, same module name

All four classifier jars declare module `com.amazon.corretto.crypto.provider`.
Putting more than one on the same `--module-path` is a hard JPMS error.
But the **test JVM** runs on the host OS and the **Docker child** runs
on linux — they generally need different classifiers.

**Fix:** two separate Gradle configurations
(`testFixturesRuntimeOnly` and `accpDockerBundle`), each carrying exactly
one classifier. `copyDockerizedApp` excludes any `AmazonCorrettoCryptoProvider-*.jar`
coming from the test-worker classpath and adds back the
`accpDockerBundle` jar.

### 6. Apple Silicon native-arch mismatch — silent zero-services state

After all of the above, the child JVM logged
`ACCP registered: AmazonCorrettoCryptoProvider 2.5.0` but every
`Signature.getInstance(...)` failed with `NoSuchAlgorithmException`.

A diagnostic added to `ConsensusNodeMain` revealed
**`accp.getServices().size() = 0`** — even `Signature.RSASSA-PSS` came
back null. The provider was registered as a Java object but exposed no
services, because **the native library failed to load**.

The container was running native `linux-aarch_64` (Apple Silicon /
Docker Desktop), but the bundle shipped the `linux-x86_64` jar. The
JNI native library didn't match, the loader failed, and ACCP entered
a degraded "no-services" state instead of crashing loudly.

**Fix:** auto-detect the host arch when picking the Docker classifier
(matches the default Docker Desktop behavior of running native-arch
containers). Override available via `-PaccpDockerClassifier=…` for
forced qemu cases.

```kotlin
val dockerAccpClassifier: String = providers.gradleProperty("accpDockerClassifier").orNull
    ?: when (System.getProperty("os.arch").lowercase()) {
        "aarch64", "arm64" -> "linux-aarch_64"
        else -> "linux-x86_64"
    }
```

### 7. ACCP's `KeyFactory.Ed25519` is missing

Side finding from the diagnostic probes: `Signature.Ed25519` and
`KeyPairGenerator.Ed25519` are registered, but
`KeyFactory.Ed25519` and `KeyFactory.EdDSA` come back `null`. ACCP
2.5.0 doesn't expose a `KeyFactory` for Ed25519 in this build.

Currently harmless — the consensus signing path uses `Signature` not
`KeyFactory`. Worth knowing if any future code does
`KeyFactory.getInstance("Ed25519", "AmazonCorrettoCryptoProvider")` —
it would silently fall through to the next provider.

## Achievements

- **Cross-platform integration** — works on Apple Silicon Mac and on Linux
  amd64 / arm64 with auto-detection.
- **No-effect-when-absent** — reflection-based load means dropping the
  ACCP dep removes ACCP without breaking anything else.
- **Defensive guard** — `SigningFactory.setDefaultImplementation` throws
  if registration runs after any signer/verifier is created, so an
  ordering regression surfaces loudly instead of silently using the wrong
  provider.
- **Diagnostic logging** — `ACCP registered`, JVM version, total service
  count, every service, and explicit probes for the algorithms we care
  about — all in `sloth-node-0.log`. Trivial to confirm ACCP is healthy
  without re-running.
- **Measured improvement** — 15% lower average latency, 22% lower p95,
  18% more bytes/sec through TLS, paid for by allocation churn that ZGC
  absorbs without measurable pause cost.

## Files touched

| File | Purpose |
|---|---|
| `hiero-dependency-versions/build.gradle.kts` | Catalog entry mapping the ACCP module name to its GAV. |
| `platform-sdk/consensus-sloth/build.gradle.kts` | Host-detection, two ACCP classifier configurations, modified `copyDockerizedApp` to substitute the Docker classifier into `lib/`. |
| `platform-sdk/consensus-utility/src/main/java/org/hiero/consensus/crypto/SigningImplementation.java` | New `RSA_ACCP` / `ED25519_ACCP` values. |
| `platform-sdk/consensus-utility/src/main/java/org/hiero/consensus/crypto/SigningFactory.java` | `setDefaultImplementation(...)` + fail-loud guard. Default map currently set to RSA_ACCP / ED25519_ACCP. |
| `platform-sdk/consensus-sloth/src/testFixtures/.../ConsensusNodeMain.java` | Reflection-based ACCP registration with diagnostic logging in the actual child JVM that runs consensus. |
| `platform-sdk/consensus-sloth/src/testFixtures/.../DockerMain.java` | Reverted to its pre-ACCP state — orchestrator JVM does no crypto. |

## Open follow-ups

- **Drop the diagnostic logging** in `ConsensusNodeMain.registerAccpIfAvailable()`
  once you've taken whatever evidence you need. ~30 lines per startup, harmless
  but noisy.
- **Attribution** — to learn how much of the 15% comes from Ed25519 vs from
  TLS record-layer crypto, run with only `RSA_ACCP` overridden (Ed25519
  on Sodium). If perf reverts to ~3195 μs the win was Ed25519; if it stays
  near 2719 μs the win was TLS / RSA-PSS.
- **`KeyFactory.Ed25519` gap** — verify nothing in the production node ever
  asks `KeyFactory.getInstance("Ed25519", "AmazonCorrettoCryptoProvider")`.
- **`linux-aarch_64` vs `linux-x86_64` Docker images** in CI — if you ever
  pin the container to a specific arch in CI, set `-PaccpDockerClassifier=…`
  so the bundle matches the container regardless of the CI host's arch.