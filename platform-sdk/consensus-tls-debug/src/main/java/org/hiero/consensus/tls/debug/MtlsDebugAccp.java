// SPDX-License-Identifier: Apache-2.0
package org.hiero.consensus.tls.debug;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.CountDownLatch;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * ACCP + BCJSSE benchmark variant.
 *
 * <p>Measures handshake latency with and without the Amazon Corretto Crypto Provider
 * installed in the JCA provider chain. ACCP replaces classical crypto primitives
 * (RSA, ECDH, AES-GCM) with AWS-LC-backed implementations that are significantly
 * faster than BC's pure-Java implementations.
 *
 * <p>BCJSSE uses a {@code JcaJceHelper} to look up its underlying crypto primitives.
 * When we construct {@code new BouncyCastleJsseProvider()} without passing a specific
 * provider, BCJSSE uses {@code DefaultJcaJceHelper}, which walks the global JCA
 * provider chain in registration order. By registering ACCP first, we ensure ACCP
 * handles classical operations, with BC as a fallback for anything ACCP doesn't
 * support (like ML-KEM, which ACCP omits from its default maven artifact).
 *
 * <p>Usage:
 * <pre>
 *   ./gradlew :consensus-tls-debug:run --args="--accp"              # with ACCP
 *   ./gradlew :consensus-tls-debug:run --args="--accp --no-accp"    # without, for comparison
 *   ./gradlew :consensus-tls-debug:run --args="--accp --iterations=500"
 * </pre>
 */
public final class MtlsDebugAccp {

    private static final String TLS_VERSION = "TLSv1.3";
    private static final String TLS_SUITE = "TLS_AES_256_GCM_SHA384";
    private static String[] namedGroups = {"x25519", "secp384r1"};
    private static boolean sunjsse = false;
    private static final String[] SIG_SCHEMES = {
            // CertificateVerify schemes (TLS 1.3 §4.2.3): ECDSA/ed25519/RSA-PSS only.
            "ecdsa_secp384r1_sha384",
            "ecdsa_secp256r1_sha256",
            "ed25519",
            "rsa_pss_rsae_sha256",
            "rsa_pss_rsae_sha384",
            // Cert-chain-acceptable scheme: matches prod CA cert sig (SHA384withRSA, PKCS#1 v1.5).
            // TLS 1.3 forbids rsa_pkcs1_* in CertificateVerify but permits it for cert signatures;
            // BCJSSE filters this entry out of signature_algorithms and keeps it in
            // signature_algorithms_cert when building the ClientHello/CertificateRequest.
            "rsa_pkcs1_sha384",
    };
    private static final int RSA_KEY_SIZE = 3072;
    private static final int EC_KEY_SIZE = 384;
    private static final String CERT_SIG_ALGO = "SHA384withRSA";
    private static final char[] KS_PASS = "debug".toCharArray();

    static void main(String[] args) throws Exception {
        boolean useAccp = true;
        boolean hybridPq = false;
        boolean sunjsse = false;
        int iterations = 100;
        int warmup = 20;
        for (String arg : args) {
            if ("--no-accp".equals(arg)) {
                useAccp = false;
            } else if ("--mlkem".equals(arg)) {
                hybridPq = true;
            } else if ("--sunjsse".equals(arg)) {
                sunjsse = true;
            } else if (arg.startsWith("--iterations=")) {
                iterations = Integer.parseInt(arg.substring("--iterations=".length()));
            } else if (arg.startsWith("--warmup=")) {
                warmup = Integer.parseInt(arg.substring("--warmup=".length()));
            }
        }

        if (hybridPq && sunjsse) {
            System.out.println("WARNING: SunJSSE on JDK 25 does not support X25519MLKEM768. "
                    + "The --mlkem flag will be silently ignored by SunJSSE and x25519 will be used instead.");
        }

        if (hybridPq) {
            namedGroups = new String[]{"X25519MLKEM768", "secp384r1"};
        }

        MtlsDebugAccp.sunjsse = sunjsse;

        // --- Provider registration ---
        if (useAccp) {
            try {
                final Class<?> accpClass = Class.forName("com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider");
                final Provider accp = (Provider) accpClass.getField("INSTANCE").get(null);
                Security.insertProviderAt(accp, 1);
                System.out.println("Registered ACCP: " + accp.getName() + " " + accp.getVersionStr());
            } catch (Throwable t) {
                System.out.println("ACCP not available: " + t.getClass().getSimpleName() + " " + t.getMessage());
                useAccp = false;
            }
        } else {
            System.out.println("ACCP registration skipped (--no-accp)");
        }

        final BouncyCastleProvider bcProv = new BouncyCastleProvider();
        Security.addProvider(bcProv);
        // Pin BCJSSE to BC to ensure X25519MLKEM768 works correctly.
        // Both JDK 25's SunJCE and ACCP (even locally built with ML-KEM) provide ML-KEM with
        // parameter spec classes incompatible with BC's MLKEMParameterSpec. When BCJSSE's
        // KemUtil.getKeyPairGenerator walks the global provider chain, it finds one of these
        // incompatible implementations first, calls initialize() with BC's param spec, gets
        // an InvalidAlgorithmParameterException, and silently disables X25519MLKEM768.
        //
        // Pinning to BC bypasses the global chain for crypto lookups inside BCJSSE, so ML-KEM
        // is found directly in BC (where it matches the param spec class). This is the ONLY
        // configuration we've found that correctly negotiates X25519MLKEM768 end-to-end.
        //
        // Side effect: pinning to BC also means ACCP does NOT accelerate BCJSSE's classical
        // operations (RSA, ECDH, AES-GCM) — they go directly to BC's pure-Java code, not
        // through the provider chain where ACCP would be at position 1.
        Security.addProvider(new BouncyCastleJsseProvider(bcProv));

        // Warning level to catch "disabled NamedGroup" log messages which indicate
        // a silent fallback (seen earlier when X25519MLKEM768 was dropped).
        Logger bcLogger = Logger.getLogger("org.bouncycastle.jsse.provider");
        bcLogger.setLevel(Level.WARNING);
        java.util.logging.ConsoleHandler h = new java.util.logging.ConsoleHandler();
        h.setLevel(Level.WARNING);
        bcLogger.addHandler(h);

        final String stackLabel = sunjsse ? "SunJSSE" : (useAccp ? "BCJSSE+ACCP" : "BCJSSE");
        System.out.println("=== mTLS TLS 1.3 Benchmark (" + stackLabel + ") ===");
        System.out.println("TLS version : " + TLS_VERSION);
        System.out.println("Cipher suite: " + TLS_SUITE);
        System.out.println("Named groups: " + Arrays.toString(namedGroups));
        System.out.println("Cert sig    : " + CERT_SIG_ALGO);
        System.out.println("Iterations  : " + iterations + " (after " + warmup + " warmup)");
        System.out.println("Providers   : " + providerSummary());
        System.out.println();

        // --- Generate keys / certs (same as MtlsDebugGossipPss) ---
        System.out.println("Generating keys and certificates...");
        final KeyPair caKeyPair = generateRsaKeyPair();
        final X509Certificate caCert = generateCaCertificate(caKeyPair);
        final KeyPair serverKeyPair = generateEcKeyPair();
        final X509Certificate serverCert = generateEndEntityCert("CN=server", serverKeyPair, caKeyPair, caCert);
        final KeyPair clientKeyPair = generateEcKeyPair();
        final X509Certificate clientCert = generateEndEntityCert("CN=client", clientKeyPair, caKeyPair, caCert);

        final SSLContext serverSslCtx = buildSslContext(serverKeyPair, serverCert, caCert);
        final SSLContext clientSslCtx = buildSslContext(clientKeyPair, clientCert, caCert);

        // --- Start accepting server ---
        final SSLServerSocket serverSocket = (SSLServerSocket) serverSslCtx.getServerSocketFactory()
                .createServerSocket(0, 100, InetAddress.getLoopbackAddress());
        configureSsl(serverSocket);
        final int port = serverSocket.getLocalPort();

        final Thread acceptor = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    final SSLSocket accepted = (SSLSocket) serverSocket.accept();
                    // Drive the handshake and close
                    accepted.getSession().getPeerCertificates();
                    accepted.close();
                } catch (final Exception e) {
                    if (!serverSocket.isClosed()) {
                        System.err.println("accept error: " + e.getMessage());
                    }
                    return;
                }
            }
        }, "acceptor");
        acceptor.setDaemon(true);
        acceptor.start();

        // --- Warmup ---
        System.out.println("Warming up (" + warmup + " handshakes)...");
        for (int i = 0; i < warmup; i++) {
            singleHandshake(clientSslCtx, port);
        }

        // --- Benchmark ---
        System.out.println("Measuring (" + iterations + " handshakes)...");
        final long[] samples = new long[iterations];
        long total = 0;
        for (int i = 0; i < iterations; i++) {
            final long start = System.nanoTime();
            singleHandshake(clientSslCtx, port);
            final long elapsed = System.nanoTime() - start;
            samples[i] = elapsed;
            total += elapsed;
        }

        serverSocket.close();

        // --- Report ---
        Arrays.sort(samples);
        final double meanMs = (total / (double) iterations) / 1_000_000.0;
        final double medianMs = samples[iterations / 2] / 1_000_000.0;
        final double p95Ms = samples[(int) (iterations * 0.95)] / 1_000_000.0;
        final double p99Ms = samples[(int) (iterations * 0.99)] / 1_000_000.0;
        final double minMs = samples[0] / 1_000_000.0;
        final double maxMs = samples[iterations - 1] / 1_000_000.0;

        System.out.println();
        System.out.println("=== Results ===");
        System.out.printf("ACCP     : %s%n", useAccp ? "enabled" : "disabled");
        System.out.printf("Mean     : %.3f ms%n", meanMs);
        System.out.printf("Median   : %.3f ms%n", medianMs);
        System.out.printf("p95      : %.3f ms%n", p95Ms);
        System.out.printf("p99      : %.3f ms%n", p99Ms);
        System.out.printf("Min      : %.3f ms%n", minMs);
        System.out.printf("Max      : %.3f ms%n", maxMs);
        System.out.printf("Throughput: %.1f handshakes/sec%n", 1000.0 / meanMs);
    }

    private static void singleHandshake(final SSLContext clientSslCtx, final int port) throws Exception {
        final SSLSocket clientSocket = (SSLSocket) clientSslCtx.getSocketFactory().createSocket();
        configureSsl(clientSocket);
        clientSocket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
        clientSocket.startHandshake();
        clientSocket.getSession().getPeerCertificates();
        clientSocket.close();
    }

    private static String providerSummary() {
        final StringBuilder sb = new StringBuilder();
        for (final Provider p : Security.getProviders()) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(p.getName());
        }
        return sb.toString();
    }

    // ---- Key generation ----

    private static KeyPair generateRsaKeyPair() throws Exception {
        final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");
        gen.initialize(RSA_KEY_SIZE, SecureRandom.getInstanceStrong());
        return gen.generateKeyPair();
    }

    private static KeyPair generateEcKeyPair() throws Exception {
        final KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(EC_KEY_SIZE, SecureRandom.getInstanceStrong());
        return gen.generateKeyPair();
    }

    private static X509Certificate generateCaCertificate(KeyPair caKeyPair) throws Exception {
        final Date notBefore = Date.from(java.time.Instant.parse("2000-01-01T00:00:00Z"));
        final Date notAfter = Date.from(java.time.Instant.parse("2100-01-01T00:00:00Z"));

        final X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Principal("CN=DebugCA"),
                BigInteger.valueOf(1),
                notBefore, notAfter,
                new X500Principal("CN=DebugCA"),
                caKeyPair.getPublic());

        builder.addExtension(Extension.subjectKeyIdentifier, false,
                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(caKeyPair.getPublic()));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(builder.build(
                        new JcaContentSignerBuilder(CERT_SIG_ALGO).setProvider("BC").build(caKeyPair.getPrivate())));
    }

    private static X509Certificate generateEndEntityCert(
            String dn, KeyPair entityKeyPair, KeyPair caKeyPair, X509Certificate caCert) throws Exception {
        final Date notBefore = Date.from(java.time.Instant.parse("2000-01-01T00:00:00Z"));
        final Date notAfter = Date.from(java.time.Instant.parse("2100-01-01T00:00:00Z"));

        final X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                caCert.getSubjectX500Principal(),
                new BigInteger(64, SecureRandom.getInstanceStrong()),
                notBefore, notAfter,
                new X500Principal(dn),
                entityKeyPair.getPublic());

        builder.addExtension(Extension.subjectKeyIdentifier, false,
                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(entityKeyPair.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caCert));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.keyAgreement));
        builder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(new KeyPurposeId[]{
                        KeyPurposeId.id_kp_serverAuth,
                        KeyPurposeId.id_kp_clientAuth
                }));

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(builder.build(
                        new JcaContentSignerBuilder(CERT_SIG_ALGO).setProvider("BC").build(caKeyPair.getPrivate())));
    }

    // ---- SSL setup ----

    private static SSLContext buildSslContext(
            KeyPair entityKeyPair, X509Certificate entityCert, X509Certificate caCert) throws Exception {
        if (sunjsse) {
            // SunJSSE uses PKCS12 keystore and SunX509 KMF/TMF (matches gossip-style setup).
            // Only the entity cert is in the keystore chain — SunJSSE's PKIX looks up the CA
            // from the trust store during handshake, so no need to include it in the chain.
            final KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, KS_PASS);
            keyStore.setKeyEntry("key", entityKeyPair.getPrivate(), KS_PASS,
                    new java.security.cert.Certificate[]{entityCert});

            final KeyStore trustStore = KeyStore.getInstance("PKCS12");
            trustStore.load(null, KS_PASS);
            trustStore.setCertificateEntry("ca", caCert);

            final KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(keyStore, KS_PASS);

            final TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(trustStore);

            final SSLContext ctx = SSLContext.getInstance(TLS_VERSION);
            ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), SecureRandom.getInstanceStrong());
            return ctx;
        }

        // BCJSSE path
        final KeyStore keyStore = KeyStore.getInstance("BKS", "BC");
        keyStore.load(null, KS_PASS);
        keyStore.setKeyEntry("key", entityKeyPair.getPrivate(), KS_PASS,
                new java.security.cert.Certificate[]{entityCert, caCert});
        keyStore.setCertificateEntry("ca", caCert);

        final KeyStore trustStore = KeyStore.getInstance("BKS", "BC");
        trustStore.load(null, KS_PASS);
        trustStore.setCertificateEntry("ca", caCert);

        final KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", "BCJSSE");
        kmf.init(keyStore, KS_PASS);

        final TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", "BCJSSE");
        tmf.init(trustStore);

        final SSLContext ctx = SSLContext.getInstance(TLS_VERSION, "BCJSSE");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), SecureRandom.getInstanceStrong());
        return ctx;
    }

    private static void configureSsl(SSLServerSocket ss) {
        ss.setEnabledProtocols(new String[]{TLS_VERSION});
        ss.setEnabledCipherSuites(new String[]{TLS_SUITE});
        ss.setNeedClientAuth(true);
        final SSLParameters params = ss.getSSLParameters();
        params.setNamedGroups(namedGroups);
        params.setSignatureSchemes(SIG_SCHEMES);
        ss.setSSLParameters(params);
    }

    private static void configureSsl(SSLSocket s) {
        s.setEnabledProtocols(new String[]{TLS_VERSION});
        s.setEnabledCipherSuites(new String[]{TLS_SUITE});
        s.setNeedClientAuth(true);
        final SSLParameters params = s.getSSLParameters();
        params.setNamedGroups(namedGroups);
        params.setSignatureSchemes(SIG_SCHEMES);
        s.setSSLParameters(params);
    }
}