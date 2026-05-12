// SPDX-License-Identifier: Apache-2.0
plugins { id("org.hiero.gradle.module.application") }

description = "mTLS TLS 1.3 Debug Tool"

application { mainClass = "org.hiero.consensus.tls.debug.MtlsDebugAccp" }


// ACCP (Amazon Corretto Crypto Provider) as a runtime-only dependency.
// Using a locally-built ACCP jar with ML-KEM support enabled (built with -DTARGET_JDK_VERSION=17).
// The default maven artifact omits ML-KEM for JDK 8+ compatibility.
// Loaded via reflection at runtime so no module-info requirement.
dependencies {
    runtimeOnly(files("libs/accp-mlkem.jar"))
}