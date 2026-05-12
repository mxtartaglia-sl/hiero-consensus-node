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
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Reproducer for the production gossip TLS configuration: RSA-3072 self-signed CA
 * (signed with RSA-PSS-SHA384) + ML-DSA-65 agrCert (public key is ML-DSA-65,
 * signed by the RSA CA with RSA-PSS-SHA384). BCJSSE pinned to BC (the {@code
 * BouncyCastleJsseProvider(bcProv)} constructor, not the hybrid {@code
 * JcaJceHelper}). Same TLS 1.3 cipher suite, same named groups, same signature
 * schemes list as {@code CryptoConstants}.
 *
 * <p>Sloth fails on this exact shape with {@code TlsFatalAlert: handshake_failure
 * "found no selectable cipher suite"}. This variant lets us reproduce that failure
 * end-to-end in seconds rather than minutes per docker round-trip.
 *
 * <p>Usage: {@code ./gradlew :consensus-tls-debug:run --args="--mixed-mldsa"}
 */
public final class MtlsDebugMixedMlDsaAgr {

    private static final String TLS_VERSION = "TLSv1.3";
    private static final String TLS_SUITE = "TLS_AES_256_GCM_SHA384";

    // Production-shape: hybrid PQ kx + secp384r1 (structurally required).
    private static final String[] NAMED_GROUPS = {"X25519MLKEM768", "secp384r1"};

    // Production-shape signature schemes (CryptoConstants.TLS_SIGNATURE_SCHEMES verbatim).
    private static final String[] SIG_SCHEMES = {
            "mldsa65",
            "mldsa44",
            "mldsa87",
            "ecdsa_secp384r1_sha384",
            "ecdsa_secp256r1_sha256",
            "ed25519",
            "ed448",
            "rsa_pss_rsae_sha256",
            "rsa_pss_rsae_sha384",
    };

    private static final int RSA_KEY_SIZE = 3072;
    private static final String CA_SIG_ALGO = "SHA384withRSAandMGF1"; // RSA-PSS — production sigKey is RSA, signs cert chain with PSS
    private static final char[] KS_PASS = "debug".toCharArray();

    static void main(String[] args) throws Exception {
        // BCJSSE pinned to BC (production registration shape: BouncyCastleJsseProvider(bcProv)).
        final BouncyCastleProvider bcProv = new BouncyCastleProvider();
        Security.addProvider(bcProv);
        Security.addProvider(new BouncyCastleJsseProvider(bcProv));

        Logger.getLogger("org.bouncycastle.jsse.provider").setLevel(Level.WARNING);
        final java.util.logging.ConsoleHandler h = new java.util.logging.ConsoleHandler();
        h.setLevel(Level.WARNING);
        Logger.getLogger("org.bouncycastle.jsse.provider").addHandler(h);

        System.out.println("=== Mixed-chain reproducer: RSA CA + ML-DSA-65 agrCert ===");
        System.out.println("Provider    : BCJSSE pinned to BC (production shape)");
        System.out.println("Named groups: " + Arrays.toString(NAMED_GROUPS));
        System.out.println("Sig schemes : " + Arrays.toString(SIG_SCHEMES));
        System.out.println("CA sig algo : " + CA_SIG_ALGO + "  (RSA-PSS — production sigKey)");
        System.out.println("agrCert key : ML-DSA-65");
        System.out.println();

        // --- 1a. Server's RSA-3072 self-signed CA (its sigCert), signed with RSA-PSS ---
        System.out.println("[1a] Generating SERVER RSA-" + RSA_KEY_SIZE + " self-signed CA (PSS-signed)...");
        final KeyPair serverCaKeyPair = generateRsaKeyPair();
        final X509Certificate serverCaCert = generateCaCertificate(serverCaKeyPair, "CN=ProdShapeCA-server");
        System.out.println("    CA DN     : " + serverCaCert.getSubjectX500Principal());
        System.out.println("    CA sig alg: " + serverCaCert.getSigAlgName());

        // --- 1b. Client's INDEPENDENT RSA-3072 self-signed CA (different from server's) ---
        System.out.println("[1b] Generating CLIENT RSA-" + RSA_KEY_SIZE + " self-signed CA (PSS-signed)...");
        final KeyPair clientCaKeyPair = generateRsaKeyPair();
        final X509Certificate clientCaCert = generateCaCertificate(clientCaKeyPair, "CN=ProdShapeCA-client");
        System.out.println("    CA DN     : " + clientCaCert.getSubjectX500Principal());

        // --- 2. ML-DSA-65 server agrCert, signed by SERVER's RSA CA ---
        System.out.println("[2] Generating server ML-DSA-65 agrCert (signed by SERVER CA with PSS)...");
        final KeyPair serverAgrKeyPairFresh = generateMlDsaKeyPair();
        // Round-trip the key through PKCS#8 to mimic sloth's proto serialize/deserialize path.
        // This is what KeysAndCertsConverter.toProto / fromProto does end-to-end.
        final KeyPair serverAgrKeyPair = roundTripKeyPair(serverAgrKeyPairFresh);
        System.out.println("    agrKey class (pre-rt) : " + serverAgrKeyPairFresh.getPrivate().getClass().getName());
        System.out.println("    agrKey class (post-rt): " + serverAgrKeyPair.getPrivate().getClass().getName());
        System.out.println("    agrKey alg (post-rt)  : " + serverAgrKeyPair.getPrivate().getAlgorithm());
        final X509Certificate serverAgrCertFresh =
                generateMlDsaAgrCert("CN=server", serverAgrKeyPair, serverCaKeyPair, serverCaCert);
        // Round-trip through CertificateFactory WITHOUT a pinned provider — exactly what sloth's
        // KeysAndCertsConverter does. On JDK 25 the default X.509 CertificateFactory parses the
        // cert's SubjectPublicKeyInfo using SunJCE's ML-DSA class, while the private key is BC's.
        // If BCJSSE checks the cert.publicKey vs keystore privateKey for class match, this is
        // where the mismatch is introduced.
        final X509Certificate serverAgrCert = roundTripCertificate(serverAgrCertFresh);
        System.out.println("    cert.pubKey class (pre-rt) : " + serverAgrCertFresh.getPublicKey().getClass().getName());
        System.out.println("    cert.pubKey class (post-rt): " + serverAgrCert.getPublicKey().getClass().getName());
        System.out.println("    agrCert DN     : " + serverAgrCert.getSubjectX500Principal());
        System.out.println("    agrCert sig alg: " + serverAgrCert.getSigAlgName());
        System.out.println("    agrCert pubkey : " + serverAgrCert.getPublicKey().getAlgorithm());

        // --- 3. ML-DSA-65 client agrCert, signed by CLIENT's RSA CA ---
        System.out.println("[3] Generating client ML-DSA-65 agrCert (signed by CLIENT CA with PSS)...");
        final KeyPair clientAgrKeyPair = roundTripKeyPair(generateMlDsaKeyPair());
        final X509Certificate clientAgrCert =
                roundTripCertificate(generateMlDsaAgrCert("CN=client", clientAgrKeyPair, clientCaKeyPair, clientCaCert));

        // --- 4. SSL contexts: each side trusts the OTHER side's CA only (production roster shape) ---
        System.out.println("[4] Building SSL contexts (each side trusts only peer's CA)...");
        // Server keystore = its own chain; trust store = client's CA only.
        final SSLContext serverSslCtx = buildSslContext(serverAgrKeyPair, serverAgrCert, serverCaCert, clientCaCert);
        // Client keystore = its own chain; trust store = server's CA only.
        final SSLContext clientSslCtx = buildSslContext(clientAgrKeyPair, clientAgrCert, clientCaCert, serverCaCert);

        // --- 5. Server ---
        final SSLServerSocket serverSocket = (SSLServerSocket) serverSslCtx.getServerSocketFactory()
                .createServerSocket(0, 1, InetAddress.getLoopbackAddress());
        configureSsl(serverSocket);
        final int port = serverSocket.getLocalPort();
        System.out.println("[5] Server listening on localhost:" + port);

        final Thread serverThread = startServerThread(serverSocket);

        // --- 6. Client connect + handshake ---
        System.out.println("[6] Client connecting...");
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
        out.println("hello-mixed-mldsa");
        System.out.println("    [client] Reply    : " + in.readLine());

        clientSocket.close();
        serverThread.join(5000);
        serverSocket.close();

        System.out.println();
        System.out.println("=== HANDSHAKE SUCCESS ===");
        System.out.println("    Mixed chain (RSA CA + ML-DSA-65 agrCert signed by RSA-PSS) IS supported.");
        System.out.println("    The sloth failure must be coming from elsewhere — investigate trust-store");
        System.out.println("    population, peer identity matching, or roster cert handling.");
    }

    private static Thread startServerThread(final SSLServerSocket serverSocket) {
        final Thread t = new Thread(() -> {
            try {
                final SSLSocket accepted = (SSLSocket) serverSocket.accept();
                accepted.startHandshake(); // force, mirroring our InboundConnectionHandler fix
                System.out.println("    [server] Accepted from " + accepted.getRemoteSocketAddress());
                System.out.println("    [server] Protocol : " + accepted.getSession().getProtocol());
                final X509Certificate peerCert =
                        (X509Certificate) accepted.getSession().getPeerCertificates()[0];
                System.out.println("    [server] Peer DN  : " + peerCert.getSubjectX500Principal());

                final BufferedReader in = new BufferedReader(new InputStreamReader(accepted.getInputStream()));
                final PrintWriter out = new PrintWriter(accepted.getOutputStream(), true);
                final String msg = in.readLine();
                System.out.println("    [server] Received : " + msg);
                out.println("echo:" + msg);
                accepted.close();
            } catch (final Exception e) {
                System.err.println("    [server] ERROR (this is expected — proves the bug):");
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

    private static KeyPair generateMlDsaKeyPair() throws Exception {
        final KeyPairGenerator gen = KeyPairGenerator.getInstance("ML-DSA-65", "BC");
        return gen.generateKeyPair();
    }

    /**
     * Round-trip an X509Certificate through CertificateFactory WITHOUT pinning a provider —
     * exactly what {@code KeysAndCertsConverter.fromProto} does. On JDK 25 with JEP 497 the
     * default X.509 factory parses the SubjectPublicKeyInfo using SunJCE's ML-DSA class, not
     * BC's. This is the suspect interaction with BC-class private keys in the keystore.
     */
    private static X509Certificate roundTripCertificate(final X509Certificate cert) throws Exception {
        // BC pinned — this is the fix. Without "BC", JDK 25's default factory parses ML-DSA
        // SPKI as sun.security.x509.NamedX509Key, and BCJSSE can't pair that with the
        // BC-class private key in the keystore.
        final java.security.cert.CertificateFactory cf =
                java.security.cert.CertificateFactory.getInstance("X.509", "BC");
        return (X509Certificate) cf.generateCertificate(
                new java.io.ByteArrayInputStream(cert.getEncoded()));
    }

    /**
     * Round-trip a KeyPair through PKCS#8 / X.509 encoding to mimic sloth's
     * KeysAndCertsConverter.toProto / fromProto path: getEncoded() → bytes → KeyFactory.
     * If this changes the key's behavior in any way that BCJSSE cares about, it'll show up
     * here.
     */
    private static KeyPair roundTripKeyPair(final KeyPair original) throws Exception {
        final java.security.KeyFactory kf = java.security.KeyFactory.getInstance("ML-DSA-65", "BC");
        final java.security.PrivateKey priv = kf.generatePrivate(
                new java.security.spec.PKCS8EncodedKeySpec(original.getPrivate().getEncoded()));
        final java.security.PublicKey pub = kf.generatePublic(
                new java.security.spec.X509EncodedKeySpec(original.getPublic().getEncoded()));
        return new KeyPair(pub, priv);
    }

    // ---- Certificate generation ----

    private static X509Certificate generateCaCertificate(final KeyPair caKeyPair, final String dn) throws Exception {
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
                        new JcaContentSignerBuilder(CA_SIG_ALGO).setProvider("BC").build(caKeyPair.getPrivate())));
    }

    /**
     * Generate an ML-DSA-65 agrCert: public key is ML-DSA-65, signed by the (RSA) CA with
     * RSA-PSS. This mirrors what {@code KeysAndCertsGenerator} produces in the modified
     * production code path: {@code generateCertificate(dnA, agrKeyPair, dnS, sigKeyPair,
     * agrDetRandom, schema.getSigningAlgorithm())} where schema is RSA → SHA384withRSAandMGF1.
     */
    private static X509Certificate generateMlDsaAgrCert(
            final String dn,
            final KeyPair entityKeyPair,
            final KeyPair caKeyPair,
            final X509Certificate caCert)
            throws Exception {
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
        // KeyUsage matches what KeysAndCertsGenerator's CertificateUtils.generateCertificate
        // produces — but note: keyAgreement makes no semantic sense for ML-DSA (signature-only).
        // If BCJSSE rejects the credential because the leaf's KeyUsage advertises keyAgreement
        // for a signature-only key type, this flag is the suspect.
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.keyAgreement));
        builder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(new KeyPurposeId[]{
                        KeyPurposeId.id_kp_serverAuth,
                        KeyPurposeId.id_kp_clientAuth
                }));

        // RSA-PSS-signed by the RSA CA — this is the "mixed chain" shape.
        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(builder.build(
                        new JcaContentSignerBuilder(CA_SIG_ALGO).setProvider("BC").build(caKeyPair.getPrivate())));
    }

    // ---- SSL setup (production-shape: BCJSSE pinned to BC, BKS keystore, PKIX) ----

    private static SSLContext buildSslContext(
            final KeyPair entityKeyPair,
            final X509Certificate entityCert,
            final X509Certificate ownCaCert,
            final X509Certificate peerCaCert)
            throws Exception {
        final KeyStore keyStore = KeyStore.getInstance("BKS", "BC");
        keyStore.load(null, KS_PASS);
        // Keystore chain = [agrCert, ownCaCert] — same as production gossip code.
        keyStore.setKeyEntry("key", entityKeyPair.getPrivate(), KS_PASS,
                new java.security.cert.Certificate[]{entityCert, ownCaCert});
        keyStore.setCertificateEntry("own-ca", ownCaCert);

        // Trust store contains only the PEER's CA — same as production roster shape where
        // each node's trust store has the other peers' sigCerts (not its own).
        final KeyStore trustStore = KeyStore.getInstance("BKS", "BC");
        trustStore.load(null, KS_PASS);
        trustStore.setCertificateEntry("peer-ca", peerCaCert);

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
        ss.setWantClientAuth(true);
        final SSLParameters params = ss.getSSLParameters();
        params.setNamedGroups(NAMED_GROUPS);
        params.setSignatureSchemes(SIG_SCHEMES);
        ss.setSSLParameters(params);
    }

    private static void configureSsl(final SSLSocket s) {
        s.setEnabledProtocols(new String[]{TLS_VERSION});
        s.setEnabledCipherSuites(new String[]{TLS_SUITE});
        s.setNeedClientAuth(true);
        s.setWantClientAuth(true);
        final SSLParameters params = s.getSSLParameters();
        params.setNamedGroups(NAMED_GROUPS);
        params.setSignatureSchemes(SIG_SCHEMES);
        s.setSSLParameters(params);
    }
}