// SPDX-License-Identifier: Apache-2.0
package org.hiero.consensus.tls.debug;

import java.io.BufferedReader;
import java.io.InputStreamReader;
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
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
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
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * SunJSSE benchmark variant — current production gossip stack shape.
 *
 * <p>Mirrors {@link MtlsDebugJava}'s configuration (SunJSSE, SunX509 KMF/TMF, PKCS12,
 * RSA-3072 CA signing, EC-384 agreement keys, SHA384withRSA certs, x25519 kx) but
 * adds the iteration / warmup loop from {@link MtlsDebugHybrid} so latencies are
 * directly comparable to the BCJSSE measurements.
 *
 * <p>Usage:
 * <pre>
 *   ./gradlew :consensus-tls-debug:run --args="--sunjsse-bench [--no-accp] [--iterations=N] [--warmup=N]"
 * </pre>
 *
 * <p>BC is registered as a JCA-only provider (for cert generation), NOT BCJSSE.
 * SunJSSE handles all TLS. ACCP, when enabled, registers at JCA position 1 and
 * accelerates the classical operations SunJSSE invokes through the global chain.
 */
public final class MtlsDebugSunJsseBench {

    private static final String TLS_VERSION = "TLSv1.3";
    private static final String TLS_SUITE = "TLS_AES_256_GCM_SHA384";
    private static final String KMF_TYPE = "SunX509";
    private static final String TMF_TYPE = "SunX509";
    private static final String KEYSTORE_TYPE = "pkcs12";
    private static final String JSSE_PROVIDER = "SunJSSE";
    private static final int RSA_KEY_SIZE = 3072;
    private static final int EC_KEY_SIZE = 384;
    private static final String CERT_SIG_ALGO = "SHA384withRSA"; // PKCS#1 v1.5 — production today
    private static final char[] KS_PASS = "debug".toCharArray();

    static void main(String[] args) throws Exception {
        boolean useAccp = true;
        boolean verify = false;
        int iterations = 100;
        int warmup = 20;
        for (String arg : args) {
            if ("--no-accp".equals(arg)) useAccp = false;
            else if ("--verify".equals(arg)) verify = true;
            else if (arg.startsWith("--iterations=")) iterations = Integer.parseInt(arg.substring("--iterations=".length()));
            else if (arg.startsWith("--warmup=")) warmup = Integer.parseInt(arg.substring("--warmup=".length()));
        }
        if (verify) {
            // Enable SunJSSE handshake debug — caller greps stderr for "Selected NamedGroup" etc.
            System.setProperty("javax.net.debug", "ssl:handshake");
        }

        // ACCP at JCA position 1 — SunJSSE will route classical lookups through it.
        if (useAccp) {
            try {
                final Class<?> accpClass = Class.forName("com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider");
                final Provider accp = (Provider) accpClass.getField("INSTANCE").get(null);
                Security.insertProviderAt(accp, 1);
                System.out.println("Registered ACCP: " + accp.getName() + " " + accp.getVersionStr());
            } catch (final Throwable t) {
                System.out.println("ACCP not available: " + t.getClass().getSimpleName() + " " + t.getMessage());
                useAccp = false;
            }
        }

        // BC for cert generation only (not TLS — SunJSSE handles TLS).
        Security.addProvider(new BouncyCastleProvider());

        System.out.println("=== mTLS TLS 1.3 Benchmark (SunJSSE) ===");
        System.out.println("ACCP        : " + (useAccp ? "enabled" : "disabled"));
        System.out.println("Provider    : " + JSSE_PROVIDER);
        System.out.println("KMF/TMF     : " + KMF_TYPE);
        System.out.println("Keystore    : " + KEYSTORE_TYPE);
        System.out.println("CA sig alg  : " + CERT_SIG_ALGO);
        System.out.println("Iterations  : " + iterations + " (after " + warmup + " warmup)");
        System.out.println();

        final KeyPair caKeyPair = generateRsaKeyPair();
        final X509Certificate caCert = generateCaCertificate(caKeyPair);
        final KeyPair serverKeyPair = generateEcKeyPair();
        final X509Certificate serverCert = generateEndEntityCert("CN=server", serverKeyPair, caKeyPair, caCert);
        final KeyPair clientKeyPair = generateEcKeyPair();
        final X509Certificate clientCert = generateEndEntityCert("CN=client", clientKeyPair, caKeyPair, caCert);

        final SSLContext serverSslCtx = buildSslContext(serverKeyPair, serverCert, caCert);
        final SSLContext clientSslCtx = buildSslContext(clientKeyPair, clientCert, caCert);

        final SSLServerSocket serverSocket = (SSLServerSocket) serverSslCtx.getServerSocketFactory()
                .createServerSocket(0, 100, InetAddress.getLoopbackAddress());
        configureSsl(serverSocket);
        final int port = serverSocket.getLocalPort();

        final Thread acceptor = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    final SSLSocket accepted = (SSLSocket) serverSocket.accept();
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

        if (verify) {
            final SSLSocket clientSocket = (SSLSocket) clientSslCtx.getSocketFactory().createSocket();
            configureSsl(clientSocket);
            clientSocket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
            clientSocket.startHandshake();
            final java.security.cert.Certificate[] peer = clientSocket.getSession().getPeerCertificates();
            System.out.println();
            System.out.println("=== Verify ===");
            System.out.println("Provider               : " + JSSE_PROVIDER);
            System.out.println("Negotiated protocol    : " + clientSocket.getSession().getProtocol());
            System.out.println("Negotiated cipherSuite : " + clientSocket.getSession().getCipherSuite());
            System.out.println("Peer cert subject      : " + ((java.security.cert.X509Certificate) peer[0]).getSubjectX500Principal());
            System.out.println("Peer cert sigAlg       : " + ((java.security.cert.X509Certificate) peer[0]).getSigAlgName());
            clientSocket.close();
            serverSocket.close();
            return;
        }

        System.out.println("Warming up (" + warmup + ")...");
        for (int i = 0; i < warmup; i++) {
            singleHandshake(clientSslCtx, port);
        }

        System.out.println("Measuring (" + iterations + ")...");
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

        Arrays.sort(samples);
        final double meanMs = (total / (double) iterations) / 1_000_000.0;
        System.out.println();
        System.out.println("=== Results ===");
        System.out.printf("Mean     : %.3f ms%n", meanMs);
        System.out.printf("Median   : %.3f ms%n", samples[iterations / 2] / 1_000_000.0);
        System.out.printf("p95      : %.3f ms%n", samples[(int) (iterations * 0.95)] / 1_000_000.0);
        System.out.printf("p99      : %.3f ms%n", samples[(int) (iterations * 0.99)] / 1_000_000.0);
        System.out.printf("Min      : %.3f ms%n", samples[0] / 1_000_000.0);
        System.out.printf("Max      : %.3f ms%n", samples[iterations - 1] / 1_000_000.0);
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

    private static X509Certificate generateCaCertificate(final KeyPair caKeyPair) throws Exception {
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
            final String dn, final KeyPair entityKeyPair, final KeyPair caKeyPair, final X509Certificate caCert) throws Exception {
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

    private static SSLContext buildSslContext(
            final KeyPair entityKeyPair, final X509Certificate entityCert, final X509Certificate caCert) throws Exception {
        final KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        keyStore.load(null, KS_PASS);
        keyStore.setKeyEntry("key", entityKeyPair.getPrivate(), KS_PASS,
                new java.security.cert.Certificate[]{entityCert, caCert});
        keyStore.setCertificateEntry("ca", caCert);

        final KeyStore trustStore = KeyStore.getInstance(KEYSTORE_TYPE);
        trustStore.load(null, KS_PASS);
        trustStore.setCertificateEntry("ca", caCert);

        final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KMF_TYPE, JSSE_PROVIDER);
        kmf.init(keyStore, KS_PASS);

        final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TMF_TYPE, JSSE_PROVIDER);
        tmf.init(trustStore);

        final SSLContext ctx = SSLContext.getInstance(TLS_VERSION, JSSE_PROVIDER);
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), SecureRandom.getInstanceStrong());
        return ctx;
    }

    private static void configureSsl(final SSLServerSocket ss) {
        ss.setEnabledProtocols(new String[]{TLS_VERSION});
        ss.setEnabledCipherSuites(new String[]{TLS_SUITE});
        ss.setNeedClientAuth(true);
    }

    private static void configureSsl(final SSLSocket s) {
        s.setEnabledProtocols(new String[]{TLS_VERSION});
        s.setEnabledCipherSuites(new String[]{TLS_SUITE});
        s.setNeedClientAuth(true);
    }
}