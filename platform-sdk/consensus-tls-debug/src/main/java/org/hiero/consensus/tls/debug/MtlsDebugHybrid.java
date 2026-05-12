// SPDX-License-Identifier: Apache-2.0
package org.hiero.consensus.tls.debug;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.ExemptionMechanism;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
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
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

/**
 * Hybrid BCJSSE + ACCP benchmark with a custom {@link JcaJceHelper} that routes
 * ML-KEM operations to BC and everything else to the default (ACCP-walked) chain.
 *
 * <p>Why: BCJSSE cannot use {@code DefaultJcaJceHelper} because incompatible ML-KEM
 * implementations (SunJCE, ACCP) shadow BC's, causing silent X25519MLKEM768 fallback.
 * But BCJSSE pinned to BC bypasses the global provider chain, so ACCP never gets
 * called for classical operations. This variant tries to have both: pin only ML-KEM
 * lookups to BC, let everything else walk the global chain (where ACCP is first).
 *
 * <p>Usage:
 * <pre>
 *   ./gradlew :consensus-tls-debug:run --args="--hybrid [--mlkem] [--no-accp] [--iterations=N]"
 * </pre>
 */
public final class MtlsDebugHybrid {

    private static final String TLS_VERSION = "TLSv1.3";
    private static final String TLS_SUITE = "TLS_AES_256_GCM_SHA384";
    private static String[] namedGroups = {"x25519", "secp384r1"};
    private static String[] sigSchemes = {
            "ecdsa_secp384r1_sha384",
            "ecdsa_secp256r1_sha256",
            "ed25519",
            "rsa_pss_rsae_sha256",
            "rsa_pss_rsae_sha384",
    };
    private static boolean useMlDsa = false;
    private static final int RSA_KEY_SIZE = 3072;
    private static final int EC_KEY_SIZE = 384;
    private static final String CERT_SIG_ALGO = "SHA384withRSAandMGF1";
    private static final char[] KS_PASS = "debug".toCharArray();

    static void main(String[] args) throws Exception {
        boolean useAccp = true;
        boolean hybridPq = false;
        boolean purePq = false;
        boolean verify = false;
        int iterations = 100;
        int warmup = 20;
        for (String arg : args) {
            if ("--no-accp".equals(arg)) useAccp = false;
            else if ("--mlkem".equals(arg)) hybridPq = true;
            else if ("--pure".equals(arg)) purePq = true;
            else if ("--mldsa".equals(arg)) useMlDsa = true;
            else if ("--verify".equals(arg)) verify = true;
            else if (arg.startsWith("--iterations=")) iterations = Integer.parseInt(arg.substring("--iterations=".length()));
            else if (arg.startsWith("--warmup=")) warmup = Integer.parseInt(arg.substring("--warmup=".length()));
        }

        if (purePq) {
            // Pure ML-KEM-768 (no x25519 hybrid component). draft-ietf-tls-mlkem-07.
            namedGroups = new String[]{"MLKEM768", "secp384r1"};
        } else if (hybridPq) {
            namedGroups = new String[]{"X25519MLKEM768", "secp384r1"};
        }

        if (useMlDsa) {
            // Put mldsa65 in signature_algorithms so BCJSSE includes it in the ClientHello
            // and picks ML-DSA credentials from the keystore.
            sigSchemes = new String[]{"mldsa65", "mldsa44", "mldsa87"};
        }

        // --- Provider registration ---
        if (useAccp) {
            try {
                final Class<?> accpClass = Class.forName("com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider");
                final Provider accp = (Provider) accpClass.getField("INSTANCE").get(null);
                Security.insertProviderAt(accp, 1);
                System.out.println("Registered ACCP: " + accp.getName() + " " + accp.getVersionStr()
                        + ", services exposed: " + accp.getServices().size());
                // Probe specific algorithms — if ACCP is actually intercepting, these will show
                // 'AmazonCorrettoCryptoProvider' as the provider. If ACCP is in zero-services state,
                // the chain falls through to SunJCE/SunRsaSign etc.
                try {
                    System.out.println("  AES/GCM provider     : " + javax.crypto.Cipher.getInstance("AES/GCM/NoPadding").getProvider().getName());
                    System.out.println("  SHA-384 provider     : " + java.security.MessageDigest.getInstance("SHA-384").getProvider().getName());
                    System.out.println("  RSASSA-PSS provider  : " + java.security.Signature.getInstance("RSASSA-PSS").getProvider().getName());
                    System.out.println("  HmacSHA384 provider  : " + javax.crypto.Mac.getInstance("HmacSHA384").getProvider().getName());
                } catch (final Throwable t) {
                    System.out.println("  ACCP probe failed: " + t);
                }
            } catch (Throwable t) {
                System.out.println("ACCP not available: " + t.getClass().getSimpleName() + " " + t.getMessage());
                useAccp = false;
            }
        }

        final BouncyCastleProvider bcProv = new BouncyCastleProvider();
        Security.addProvider(bcProv);

        // Custom JcaTlsCryptoProvider with hybrid helper.
        // ML-KEM lookups go to BC (avoiding the parameter spec conflict).
        // Everything else:
        //   - ACCP registered → route through the global chain (ACCP intercepts at position 1).
        //   - ACCP not registered → pin to BC (production fallback intent: BCJSSE on BC, not on Sun JCA).
        //
        // Without this conditional, `DefaultJcaJceHelper` walks the chain and finds
        // SunRsaSign/SunEC/SunJCE first, since BC is added with addProvider (end of chain).
        // That makes the no-ACCP measurements equivalent to "BCJSSE on Sun JCA" rather than
        // the intended "BCJSSE on BC" production fallback.
        final JcaJceHelper chainLegHelper = useAccp
                ? new DefaultJcaJceHelper()
                : new ProviderJcaJceHelper(bcProv);
        final JcaJceHelper hybridHelper = new HybridJcaJceHelper(
                new ProviderJcaJceHelper(bcProv),  // BC-pinned for ML-KEM (always)
                chainLegHelper);

        final JcaTlsCryptoProvider cryptoProvider = new JcaTlsCryptoProvider() {
            @Override
            public JcaJceHelper getHelper() {
                return hybridHelper;
            }
        };

        Security.addProvider(new BouncyCastleJsseProvider(false, cryptoProvider));

        Logger bcLogger = Logger.getLogger("org.bouncycastle.jsse.provider");
        if (verify) {
            // Enable FINE logging so the script can grep for negotiated NamedGroup / SignatureScheme.
            bcLogger.setLevel(Level.FINE);
            final java.util.logging.ConsoleHandler vh = new java.util.logging.ConsoleHandler();
            vh.setLevel(Level.FINE);
            bcLogger.addHandler(vh);
        } else {
            bcLogger.setLevel(Level.WARNING);
            final java.util.logging.ConsoleHandler h = new java.util.logging.ConsoleHandler();
            h.setLevel(Level.WARNING);
            bcLogger.addHandler(h);
        }

        System.out.println("=== mTLS TLS 1.3 Benchmark (BCJSSE + Hybrid JCA helper) ===");
        System.out.println("ACCP        : " + (useAccp ? "enabled" : "disabled"));
        final String mode;
        if (purePq) mode = "MLKEM768 (pure PQ)";
        else if (hybridPq) mode = "X25519MLKEM768 (hybrid PQ)";
        else mode = "x25519 (classical)";
        System.out.println("Mode        : " + mode);
        System.out.println("Named groups: " + Arrays.toString(namedGroups));
        System.out.println("Iterations  : " + iterations + " (after " + warmup + " warmup)");
        System.out.println();

        // --- Generate keys / certs ---
        final KeyPair caKeyPair;
        final X509Certificate caCert;
        final KeyPair serverKeyPair;
        final X509Certificate serverCert;
        final KeyPair clientKeyPair;
        final X509Certificate clientCert;
        if (useMlDsa) {
            // Fully PQ auth: ML-DSA-65 CA self-signed, ML-DSA-65 entity certs signed by CA.
            caKeyPair = generateMlDsaKeyPair();
            caCert = generateCaCertificateMlDsa(caKeyPair);
            serverKeyPair = generateMlDsaKeyPair();
            serverCert = generateEndEntityCertMlDsa("CN=server", serverKeyPair, caKeyPair, caCert);
            clientKeyPair = generateMlDsaKeyPair();
            clientCert = generateEndEntityCertMlDsa("CN=client", clientKeyPair, caKeyPair, caCert);
        } else {
            caKeyPair = generateRsaKeyPair();
            caCert = generateCaCertificate(caKeyPair);
            serverKeyPair = generateEcKeyPair();
            serverCert = generateEndEntityCert("CN=server", serverKeyPair, caKeyPair, caCert);
            clientKeyPair = generateEcKeyPair();
            clientCert = generateEndEntityCert("CN=client", clientKeyPair, caKeyPair, caCert);
        }

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
            // Single handshake, capture session info, exit. The FINE-level BCJSSE logs
            // include "Selected NamedGroup: ..." etc. on stderr — caller greps externally.
            final SSLSocket clientSocket = (SSLSocket) clientSslCtx.getSocketFactory().createSocket();
            configureSsl(clientSocket);
            clientSocket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
            clientSocket.startHandshake();
            final java.security.cert.Certificate[] peer = clientSocket.getSession().getPeerCertificates();
            System.out.println();
            System.out.println("=== Verify ===");
            System.out.println("Configured namedGroups : " + Arrays.toString(namedGroups));
            System.out.println("Configured sigSchemes  : " + Arrays.toString(sigSchemes));
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

    // ---- Custom helper that routes ML-KEM to BC, everything else to the global chain ----

    static final class HybridJcaJceHelper implements JcaJceHelper {
        private final JcaJceHelper mlkem;   // for ML-KEM algorithms
        private final JcaJceHelper chain;   // for everything else (walks global provider chain)

        HybridJcaJceHelper(final JcaJceHelper mlkem, final JcaJceHelper chain) {
            this.mlkem = mlkem;
            this.chain = chain;
        }

        private boolean isMlKem(String algorithm) {
            return algorithm != null && algorithm.startsWith("ML-KEM");
        }

        @Override
        public Cipher createCipher(String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
            return (isMlKem(algorithm) ? mlkem : chain).createCipher(algorithm);
        }

        @Override
        public Mac createMac(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
            return chain.createMac(algorithm);
        }

        @Override
        public KeyAgreement createKeyAgreement(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
            return (isMlKem(algorithm) ? mlkem : chain).createKeyAgreement(algorithm);
        }

        @Override
        public AlgorithmParameterGenerator createAlgorithmParameterGenerator(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
            return chain.createAlgorithmParameterGenerator(algorithm);
        }

        @Override
        public AlgorithmParameters createAlgorithmParameters(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
            return chain.createAlgorithmParameters(algorithm);
        }

        @Override
        public KeyGenerator createKeyGenerator(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
            return (isMlKem(algorithm) ? mlkem : chain).createKeyGenerator(algorithm);
        }

        @Override
        public KeyFactory createKeyFactory(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
            return (isMlKem(algorithm) ? mlkem : chain).createKeyFactory(algorithm);
        }

        @Override
        public SecretKeyFactory createSecretKeyFactory(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
            return chain.createSecretKeyFactory(algorithm);
        }

        @Override
        public KeyPairGenerator createKeyPairGenerator(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
            return (isMlKem(algorithm) ? mlkem : chain).createKeyPairGenerator(algorithm);
        }

        @Override
        public MessageDigest createDigest(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
            return chain.createDigest(algorithm);
        }

        @Override
        public MessageDigest createMessageDigest(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
            return chain.createMessageDigest(algorithm);
        }

        @Override
        public Signature createSignature(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
            return chain.createSignature(algorithm);
        }

        @Override
        public CertificateFactory createCertificateFactory(String algorithm) throws NoSuchProviderException, CertificateException {
            return chain.createCertificateFactory(algorithm);
        }

        @Override
        public SecureRandom createSecureRandom(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
            return chain.createSecureRandom(algorithm);
        }

        @Override
        public CertPathBuilder createCertPathBuilder(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
            return chain.createCertPathBuilder(algorithm);
        }

        @Override
        public CertPathValidator createCertPathValidator(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
            return chain.createCertPathValidator(algorithm);
        }

        @Override
        public CertStore createCertStore(String type, CertStoreParameters params) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
            return chain.createCertStore(type, params);
        }

        @Override
        public ExemptionMechanism createExemptionMechanism(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
            return chain.createExemptionMechanism(algorithm);
        }

        @Override
        public KeyStore createKeyStore(String type) throws KeyStoreException, NoSuchProviderException {
            return chain.createKeyStore(type);
        }
    }

    // ---- Standard debug-tool scaffolding (duplicated from MtlsDebugAccp for clarity) ----

    private static void singleHandshake(final SSLContext clientSslCtx, final int port) throws Exception {
        final SSLSocket clientSocket = (SSLSocket) clientSslCtx.getSocketFactory().createSocket();
        configureSsl(clientSocket);
        clientSocket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
        clientSocket.startHandshake();
        clientSocket.getSession().getPeerCertificates();
        clientSocket.close();
    }

    private static KeyPair generateMlDsaKeyPair() throws Exception {
        // Generate via BC explicitly — keystore entries are BC-provenance.
        final KeyPairGenerator gen = KeyPairGenerator.getInstance("ML-DSA-65", "BC");
        return gen.generateKeyPair();
    }

    private static X509Certificate generateCaCertificateMlDsa(KeyPair caKeyPair) throws Exception {
        final Date notBefore = Date.from(java.time.Instant.parse("2000-01-01T00:00:00Z"));
        final Date notAfter = Date.from(java.time.Instant.parse("2100-01-01T00:00:00Z"));
        final X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Principal("CN=DebugCA-PQ"),
                BigInteger.valueOf(1),
                notBefore, notAfter,
                new X500Principal("CN=DebugCA-PQ"),
                caKeyPair.getPublic());
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(caKeyPair.getPublic()));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(builder.build(
                        new JcaContentSignerBuilder("ML-DSA-65").setProvider("BC").build(caKeyPair.getPrivate())));
    }

    private static X509Certificate generateEndEntityCertMlDsa(
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
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        builder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(new KeyPurposeId[]{
                        KeyPurposeId.id_kp_serverAuth,
                        KeyPurposeId.id_kp_clientAuth
                }));
        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(builder.build(
                        new JcaContentSignerBuilder("ML-DSA-65").setProvider("BC").build(caKeyPair.getPrivate())));
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

    private static SSLContext buildSslContext(
            KeyPair entityKeyPair, X509Certificate entityCert, X509Certificate caCert) throws Exception {
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
        params.setSignatureSchemes(sigSchemes);
        ss.setSSLParameters(params);
    }

    private static void configureSsl(SSLSocket s) {
        s.setEnabledProtocols(new String[]{TLS_VERSION});
        s.setEnabledCipherSuites(new String[]{TLS_SUITE});
        s.setNeedClientAuth(true);
        final SSLParameters params = s.getSSLParameters();
        params.setNamedGroups(namedGroups);
        params.setSignatureSchemes(sigSchemes);
        s.setSSLParameters(params);
    }
}