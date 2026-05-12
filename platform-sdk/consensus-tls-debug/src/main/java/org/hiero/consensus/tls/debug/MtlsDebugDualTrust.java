// SPDX-License-Identifier: Apache-2.0
package org.hiero.consensus.tls.debug;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
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
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
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
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

/**
 * Dual-trust-anchor experiment: prod-style classical chain in the keystore plus an
 * ML-DSA-65 self-signed cert as a second trust anchor in the trust store.
 *
 * <p>This validates the Phase 3 trust-store-extension assumption from the migration:
 * that the JSSE trust store accepts both a classical RSA self-signed CA and an
 * ML-DSA self-signed cert simultaneously, and that adding the PQ anchor does not
 * break the existing classical authentication path.
 *
 * <p>Setup mirrors the production code path (BCJSSE + hybrid {@code JcaJceHelper}
 * + ACCP + X25519MLKEM768 hybrid kx + RSA-3072 sigKey + EC-384 agrKey + PKCS#1 v1.5
 * sigCert + RSA-PSS agrCert) with two additions:
 *
 * <ol>
 *   <li>Generate an ML-DSA-65 self-signed cert (the proposed {@code pq_gossip_ca_certificate}
 *       content). Verify DER serialization round-trips through {@link CertificateFactory}
 *       — proves the bytes would load from a roster byte field.</li>
 *   <li>Add the ML-DSA cert to the trust store as a second {@code certificateEntry}
 *       alongside the classical CA.</li>
 * </ol>
 *
 * <p>The handshake itself uses classical authentication (keystore has the classical chain).
 * Success means the dual-anchor trust store doesn't disturb the existing path.
 *
 * <p>Usage: {@code ./gradlew :consensus-tls-debug:run --args="--dual-trust [--no-accp]"}
 */
public final class MtlsDebugDualTrust {

    private static final String TLS_VERSION = "TLSv1.3";
    private static final String TLS_SUITE = "TLS_AES_256_GCM_SHA384";
    // Production-style: hybrid PQ kx + secp384r1 (structurally required by BCJSSE).
    private static final String[] NAMED_GROUPS = {"X25519MLKEM768", "secp384r1"};
    // Dual-mode signature schemes:
    //   - classical schemes: what the keystore chain actually uses
    //   - rsa_pkcs1_sha384: cert-chain compat for the legacy PKCS#1 v1.5 sigCert (RFC 8446 §4.2.3)
    //   - mldsa65: advertised so BCJSSE doesn't reject the ML-DSA trust anchor's self-signature
    //              (and so peers offering ML-DSA auth would be accepted in the future)
    private static final String[] SIG_SCHEMES = {
            "ecdsa_secp384r1_sha384",
            "ecdsa_secp256r1_sha256",
            "ed25519",
            "rsa_pss_rsae_sha256",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "mldsa65",
    };

    private static final int RSA_KEY_SIZE = 3072;
    private static final int EC_KEY_SIZE = 384;
    private static final String CA_SIG_ALGO = "SHA384withRSA";          // sigCert: PKCS#1 v1.5 (unchanged)
    private static final String AGR_SIG_ALGO = "SHA384withRSAandMGF1";  // agrCert: RSA-PSS
    private static final String MLDSA_ALGO = "ML-DSA-65";
    private static final char[] KS_PASS = "debug".toCharArray();

    static void main(String[] args) throws Exception {
        boolean useAccp = true;
        for (String arg : args) {
            if ("--no-accp".equals(arg)) useAccp = false;
        }

        // --- Provider registration (matches MtlsDebugHybrid: ACCP at pos 1 → BC → BCJSSE w/ hybrid helper) ---
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

        final BouncyCastleProvider bcProv = new BouncyCastleProvider();
        Security.addProvider(bcProv);

        final JcaJceHelper hybridHelper = new MtlsDebugHybrid.HybridJcaJceHelper(
                new ProviderJcaJceHelper(bcProv),  // ML-KEM → BC
                new DefaultJcaJceHelper());        // everything else → chain (ACCP first)

        final JcaTlsCryptoProvider cryptoProvider = new JcaTlsCryptoProvider() {
            @Override
            public JcaJceHelper getHelper() {
                return hybridHelper;
            }
        };
        Security.addProvider(new BouncyCastleJsseProvider(false, cryptoProvider));

        Logger.getLogger("org.bouncycastle.jsse.provider").setLevel(Level.WARNING);

        System.out.println("=== Dual-trust hypothesis: classical chain + ML-DSA trust anchor ===");
        System.out.println("ACCP        : " + (useAccp ? "enabled" : "disabled"));
        System.out.println("Named groups: " + Arrays.toString(NAMED_GROUPS));
        System.out.println("Sig schemes : " + Arrays.toString(SIG_SCHEMES));
        System.out.println("CA sig algo : " + CA_SIG_ALGO);
        System.out.println("agr sig algo: " + AGR_SIG_ALGO);
        System.out.println();

        // --- 1. Classical chain (prod path) ---
        System.out.println("[1] Generating classical RSA-" + RSA_KEY_SIZE + " CA (PKCS#1 v1.5 self-signed)...");
        final KeyPair caKeyPair = generateRsaKeyPair();
        final X509Certificate caCert = generateClassicalCaCertificate(caKeyPair);
        System.out.println("    CA DN     : " + caCert.getSubjectX500Principal());
        System.out.println("    CA sig alg: " + caCert.getSigAlgName());

        // --- 2. ML-DSA-65 self-signed cert (the proposed pq_gossip_ca_certificate content) ---
        System.out.println("[2] Generating ML-DSA-65 self-signed cert...");
        final KeyPair mldsaKeyPair = generateMlDsaKeyPair();
        final X509Certificate mldsaCert = generateMlDsaCaCertificate(mldsaKeyPair);
        System.out.println("    PQ anchor DN  : " + mldsaCert.getSubjectX500Principal());
        System.out.println("    PQ sig alg    : " + mldsaCert.getSigAlgName());
        System.out.println("    PQ DER size   : " + mldsaCert.getEncoded().length + " bytes");

        // --- 3. Verify DER round-trip (proves the bytes would load from a roster field) ---
        System.out.println("[3] Verifying DER round-trip via CertificateFactory...");
        final byte[] derBytes = mldsaCert.getEncoded();
        final CertificateFactory cf = CertificateFactory.getInstance("X.509");
        final X509Certificate decoded = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(derBytes));
        if (!decoded.getSubjectX500Principal().equals(mldsaCert.getSubjectX500Principal())) {
            throw new IllegalStateException("DER round-trip mismatch on subject DN");
        }
        if (decoded.getEncoded().length != derBytes.length) {
            throw new IllegalStateException("DER round-trip mismatch on length");
        }
        System.out.println("    DER round-trip OK (" + derBytes.length + " bytes in/out match)");

        // --- 4. Server + client EC agrCerts signed by the classical CA with PSS ---
        System.out.println("[4] Generating server + client EC-" + EC_KEY_SIZE + " agrCerts (PSS-signed)...");
        final KeyPair serverKeyPair = generateEcKeyPair();
        final X509Certificate serverCert = generateEndEntityCert("CN=server", serverKeyPair, caKeyPair, caCert);
        final KeyPair clientKeyPair = generateEcKeyPair();
        final X509Certificate clientCert = generateEndEntityCert("CN=client", clientKeyPair, caKeyPair, caCert);
        System.out.println("    server agr sig: " + serverCert.getSigAlgName());

        // --- 5. SSL contexts with DUAL trust anchors (classical CA + ML-DSA self-signed) ---
        System.out.println("[5] Building SSL contexts with dual-anchor trust store...");
        final SSLContext serverSslCtx = buildSslContext(serverKeyPair, serverCert, caCert, mldsaCert);
        final SSLContext clientSslCtx = buildSslContext(clientKeyPair, clientCert, caCert, mldsaCert);

        // --- 6. Handshake ---
        final SSLServerSocket serverSocket = (SSLServerSocket) serverSslCtx.getServerSocketFactory()
                .createServerSocket(0, 1, InetAddress.getLoopbackAddress());
        configureSsl(serverSocket);
        final int port = serverSocket.getLocalPort();
        System.out.println("[6] Server listening on localhost:" + port);

        final Thread serverThread = startServerThread(serverSocket);

        final SSLSocket clientSocket = (SSLSocket) clientSslCtx.getSocketFactory().createSocket();
        configureSsl(clientSocket);
        clientSocket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
        clientSocket.startHandshake();

        System.out.println("    [client] Handshake complete");
        System.out.println("    [client] Protocol : " + clientSocket.getSession().getProtocol());
        System.out.println("    [client] Suite    : " + clientSocket.getSession().getCipherSuite());
        final X509Certificate peerCert = (X509Certificate) clientSocket.getSession().getPeerCertificates()[0];
        System.out.println("    [client] Peer DN  : " + peerCert.getSubjectX500Principal());
        System.out.println("    [client] Peer sig : " + peerCert.getSigAlgName());

        final PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        final BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        out.println("hello-dual-trust");
        System.out.println("    [client] Reply    : " + in.readLine());

        clientSocket.close();
        serverThread.join(5000);
        serverSocket.close();

        System.out.println();
        System.out.println("=== HYPOTHESIS CONFIRMED ===");
        System.out.println("    The JSSE trust store accepts both a classical RSA self-signed CA");
        System.out.println("    and an ML-DSA-65 self-signed cert as trust anchors simultaneously.");
        System.out.println("    The classical handshake completes normally with the PQ anchor present");
        System.out.println("    but unused (since the keystore presents the classical chain).");
        System.out.println();
        System.out.println("    This validates the Phase 3 trust-store extension piece of the migration:");
        System.out.println("    nodes can carry both gossip_ca_certificate (RSA) and pq_gossip_ca_certificate");
        System.out.println("    (ML-DSA-65) in the roster and load both into the JSSE trust store.");
    }

    // ---- SSL setup with dual trust anchors ----

    private static SSLContext buildSslContext(
            final KeyPair entityKeyPair,
            final X509Certificate entityCert,
            final X509Certificate classicalCa,
            final X509Certificate mldsaCa) throws Exception {

        // Keystore: classical chain only (entity cert + classical CA in chain).
        final KeyStore keyStore = KeyStore.getInstance("BKS", "BC");
        keyStore.load(null, KS_PASS);
        keyStore.setKeyEntry("key", entityKeyPair.getPrivate(), KS_PASS,
                new java.security.cert.Certificate[]{entityCert, classicalCa});
        keyStore.setCertificateEntry("classical-ca", classicalCa);

        // Trust store: BOTH the classical CA AND the ML-DSA self-signed cert.
        final KeyStore trustStore = KeyStore.getInstance("BKS", "BC");
        trustStore.load(null, KS_PASS);
        trustStore.setCertificateEntry("classical-ca", classicalCa);
        trustStore.setCertificateEntry("pq-ca", mldsaCa);

        // Print trust-store contents to confirm both anchors are loaded.
        System.out.println("    Trust store contents:");
        for (final String alias : Collections.list(trustStore.aliases())) {
            final X509Certificate cert = (X509Certificate) trustStore.getCertificate(alias);
            System.out.println("      " + alias + ": " + cert.getSubjectX500Principal()
                    + "  sigAlg=" + cert.getSigAlgName());
        }

        final KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", "BCJSSE");
        kmf.init(keyStore, KS_PASS);

        final TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", "BCJSSE");
        tmf.init(trustStore);

        final SSLContext ctx = SSLContext.getInstance(TLS_VERSION, "BCJSSE");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), SecureRandom.getInstanceStrong());
        return ctx;
    }

    private static void configureSsl(final SSLServerSocket ss) {
        ss.setEnabledProtocols(new String[]{TLS_VERSION});
        ss.setEnabledCipherSuites(new String[]{TLS_SUITE});
        ss.setNeedClientAuth(true);
        final SSLParameters params = ss.getSSLParameters();
        params.setNamedGroups(NAMED_GROUPS);
        params.setSignatureSchemes(SIG_SCHEMES);
        ss.setSSLParameters(params);
    }

    private static void configureSsl(final SSLSocket s) {
        s.setEnabledProtocols(new String[]{TLS_VERSION});
        s.setEnabledCipherSuites(new String[]{TLS_SUITE});
        s.setNeedClientAuth(true);
        final SSLParameters params = s.getSSLParameters();
        params.setNamedGroups(NAMED_GROUPS);
        params.setSignatureSchemes(SIG_SCHEMES);
        s.setSSLParameters(params);
    }

    // ---- Server accept thread ----

    private static Thread startServerThread(final SSLServerSocket serverSocket) {
        final Thread t = new Thread(() -> {
            try {
                final SSLSocket accepted = (SSLSocket) serverSocket.accept();
                System.out.println("    [server] Accepted from " + accepted.getRemoteSocketAddress());
                System.out.println("    [server] Protocol : " + accepted.getSession().getProtocol());
                final X509Certificate peerCert = (X509Certificate) accepted.getSession().getPeerCertificates()[0];
                System.out.println("    [server] Peer DN  : " + peerCert.getSubjectX500Principal());

                final BufferedReader in = new BufferedReader(new InputStreamReader(accepted.getInputStream()));
                final PrintWriter out = new PrintWriter(accepted.getOutputStream(), true);
                final String msg = in.readLine();
                System.out.println("    [server] Received : " + msg);
                out.println("echo:" + msg);
                accepted.close();
            } catch (final Exception e) {
                System.err.println("    [server] ERROR:");
                e.printStackTrace();
            }
        }, "mtls-server");
        t.setDaemon(true);
        t.start();
        return t;
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

    private static KeyPair generateMlDsaKeyPair() throws Exception {
        final KeyPairGenerator gen = KeyPairGenerator.getInstance(MLDSA_ALGO, "BC");
        return gen.generateKeyPair();
    }

    // ---- Certificate generation ----

    private static X509Certificate generateClassicalCaCertificate(final KeyPair caKeyPair) throws Exception {
        return generateCaCertificate(caKeyPair, "CN=DebugClassicalCA", CA_SIG_ALGO);
    }

    private static X509Certificate generateMlDsaCaCertificate(final KeyPair caKeyPair) throws Exception {
        return generateCaCertificate(caKeyPair, "CN=DebugPQTrustAnchor", MLDSA_ALGO);
    }

    private static X509Certificate generateCaCertificate(
            final KeyPair caKeyPair, final String dn, final String sigAlgo) throws Exception {
        final Date notBefore = Date.from(java.time.Instant.parse("2000-01-01T00:00:00Z"));
        final Date notAfter = Date.from(java.time.Instant.parse("2100-01-01T00:00:00Z"));

        final X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Principal(dn),
                BigInteger.valueOf(1),
                notBefore, notAfter,
                new X500Principal(dn),
                caKeyPair.getPublic());

        builder.addExtension(Extension.subjectKeyIdentifier, false,
                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(caKeyPair.getPublic()));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(builder.build(
                        new JcaContentSignerBuilder(sigAlgo).setProvider("BC").build(caKeyPair.getPrivate())));
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
                        new JcaContentSignerBuilder(AGR_SIG_ALGO).setProvider("BC").build(caKeyPair.getPrivate())));
    }
}