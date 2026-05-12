// SPDX-License-Identifier: Apache-2.0
package org.hiero.consensus.tls.debug;

import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

/**
 * Interop benchmark: BCJSSE (+ optional ACCP) Java client connecting to an
 * external TLS 1.3 server (e.g., OpenSSL {@code s_server}).
 *
 * <p>Tests that BCJSSE + AWS-LC (via ACCP) can interoperate with OpenSSL's
 * TLS 1.3 PQ implementation. Measures handshake latency for comparison against
 * the BCJSSE-to-BCJSSE benchmark.
 *
 * <p>Usage:
 * <pre>
 *   # In another terminal, start OpenSSL s_server with PQ:
 *   openssl s_server -accept 18443 -www -tls1_3 \
 *       -cert /tmp/pq-interop/server.crt -key /tmp/pq-interop/server.key \
 *       -groups X25519MLKEM768 -quiet
 *
 *   # Then run the benchmark:
 *   ./gradlew :consensus-tls-debug:run --args="--interop --ca=/tmp/pq-interop/ca.crt --host=localhost --port=18443"
 *   ./gradlew :consensus-tls-debug:run --args="--interop --no-accp --mlkem --iterations=200"
 * </pre>
 */
public final class MtlsDebugInterop {

    private static final String TLS_VERSION = "TLSv1.3";
    private static final String TLS_SUITE = "TLS_AES_256_GCM_SHA384";
    private static final char[] KS_PASS = "debug".toCharArray();

    static void main(String[] args) throws Exception {
        boolean useAccp = true;
        boolean hybridPq = false;
        boolean useHybridHelper = false;
        String caPath = "/tmp/pq-interop/ca.crt";
        String host = "localhost";
        int port = 18443;
        int iterations = 100;
        int warmup = 20;
        for (String arg : args) {
            if ("--no-accp".equals(arg)) useAccp = false;
            else if ("--mlkem".equals(arg)) hybridPq = true;
            else if ("--hybrid-helper".equals(arg)) useHybridHelper = true;
            else if (arg.startsWith("--ca=")) caPath = arg.substring("--ca=".length());
            else if (arg.startsWith("--host=")) host = arg.substring("--host=".length());
            else if (arg.startsWith("--port=")) port = Integer.parseInt(arg.substring("--port=".length()));
            else if (arg.startsWith("--iterations=")) iterations = Integer.parseInt(arg.substring("--iterations=".length()));
            else if (arg.startsWith("--warmup=")) warmup = Integer.parseInt(arg.substring("--warmup=".length()));
        }

        final String[] namedGroups = hybridPq
                ? new String[]{"X25519MLKEM768", "secp384r1"}
                : new String[]{"x25519", "secp384r1"};

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

        if (useHybridHelper) {
            // Hybrid helper: ML-KEM → BC, everything else → default chain (ACCP accelerated)
            final JcaJceHelper hybridHelper = new MtlsDebugHybrid.HybridJcaJceHelper(
                    new ProviderJcaJceHelper(bcProv),
                    new DefaultJcaJceHelper());
            final JcaTlsCryptoProvider cryptoProvider = new JcaTlsCryptoProvider() {
                @Override
                public JcaJceHelper getHelper() {
                    return hybridHelper;
                }
            };
            Security.addProvider(new BouncyCastleJsseProvider(false, cryptoProvider));
        } else {
            // Pin BCJSSE to BC for X25519MLKEM768 compatibility
            Security.addProvider(new BouncyCastleJsseProvider(bcProv));
        }

        Logger.getLogger("org.bouncycastle.jsse.provider").setLevel(Level.WARNING);

        final String stackLabel = useAccp ? "BCJSSE+ACCP" : "BCJSSE";
        System.out.println("=== Interop Benchmark (" + stackLabel + " client → external server) ===");
        System.out.println("Peer        : " + host + ":" + port);
        System.out.println("CA file     : " + caPath);
        System.out.println("Named groups: " + Arrays.toString(namedGroups));
        System.out.println("Iterations  : " + iterations + " (after " + warmup + " warmup)");
        System.out.println();

        // --- Build trust-only SSL context (no client cert — OpenSSL s_server doesn't require client auth by default) ---
        final SSLContext sslCtx = buildTrustOnlyContext(caPath);

        // --- Warmup ---
        System.out.println("Warming up (" + warmup + " handshakes)...");
        for (int i = 0; i < warmup; i++) {
            singleHandshake(sslCtx, host, port, namedGroups);
        }

        // --- Benchmark ---
        System.out.println("Measuring (" + iterations + " handshakes)...");
        final long[] samples = new long[iterations];
        long total = 0;
        for (int i = 0; i < iterations; i++) {
            final long start = System.nanoTime();
            singleHandshake(sslCtx, host, port, namedGroups);
            final long elapsed = System.nanoTime() - start;
            samples[i] = elapsed;
            total += elapsed;
        }

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

    private static void singleHandshake(
            final SSLContext sslCtx, final String host, final int port, final String[] namedGroups) throws Exception {
        final SSLSocket clientSocket = (SSLSocket) sslCtx.getSocketFactory().createSocket();
        clientSocket.setEnabledProtocols(new String[]{TLS_VERSION});
        clientSocket.setEnabledCipherSuites(new String[]{TLS_SUITE});
        final SSLParameters params = clientSocket.getSSLParameters();
        params.setNamedGroups(namedGroups);
        clientSocket.setSSLParameters(params);
        clientSocket.connect(new InetSocketAddress(host, port));
        clientSocket.startHandshake();
        clientSocket.getSession().getPeerCertificates();
        clientSocket.close();
    }

    private static SSLContext buildTrustOnlyContext(final String caPath) throws Exception {
        // Load the CA cert from PEM
        final CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        final X509Certificate caCert;
        try (final FileInputStream fis = new FileInputStream(caPath)) {
            caCert = (X509Certificate) cf.generateCertificate(fis);
        }

        final KeyStore trustStore = KeyStore.getInstance("BKS", "BC");
        trustStore.load(null, KS_PASS);
        trustStore.setCertificateEntry("ca", caCert);

        final TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", "BCJSSE");
        tmf.init(trustStore);

        final SSLContext ctx = SSLContext.getInstance(TLS_VERSION, "BCJSSE");
        ctx.init(null, tmf.getTrustManagers(), SecureRandom.getInstanceStrong());
        return ctx;
    }
}