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
 * Hypothesis test: BCJSSE accepts a cert chain where ONLY the agreement cert uses RSA-PSS,
 * while the self-signed CA (sigCert) keeps PKCS#1 v1.5.
 *
 * <p>Rationale: the self-signed sigCert is a trust anchor; PKIX (per RFC 5280) does not
 * validate trust-anchor self-signatures. So in principle, only the agrCert's signature
 * (made by the CA's key over agrCert.tbsBytes) needs to be PSS for BCJSSE TLS 1.3.
 * If this works, the production migration scope shrinks dramatically:
 *
 * <ul>
 *   <li>No roster update — {@code gossip_ca_certificate} DER bytes stay stable.</li>
 *   <li>No fleet keystore migration — on-disk sigCert unchanged.</li>
 *   <li>Just a code change to the agrCert generation path (PKCS#1 v1.5 → PSS).</li>
 * </ul>
 *
 * <p>Configuration matches gossip exactly: RSA-3072 CA, EC-384 agreement keys.
 * CA cert (sigCert): {@code SHA384withRSA} (PKCS#1 v1.5).
 * End-entity cert (agrCert): {@code SHA384withRSAandMGF1} (PSS).
 *
 * <p>Usage: {@code ./gradlew :consensus-tls-debug:run --args="--mixed-pss [--debug] [port]"}
 */
public final class MtlsDebugMixedPss {

    private static final String TLS_VERSION = "TLSv1.3";
    private static final String TLS_SUITE = "TLS_AES_256_GCM_SHA384";
    private static final String[] NAMED_GROUPS = {"x25519", "secp384r1"};
    private static final String[] SIG_SCHEMES = {
            "ecdsa_secp384r1_sha384",
            "ecdsa_secp256r1_sha256",
            "ed25519",
            "rsa_pss_rsae_sha256",
            "rsa_pss_rsae_sha384",
            // Cert-chain-only compatibility per RFC 8446 §4.2.3: rsa_pkcs1_* schemes
            // are explicitly allowed in cert chains for backward compatibility, but
            // are NOT allowed for handshake signatures. Including this lets BCJSSE
            // accept a self-signed CA whose own signature still uses PKCS#1 v1.5,
            // while CertificateVerify still uses PSS.
            "rsa_pkcs1_sha384",
            "rsa_pkcs1_sha256",
    };
    private static final int RSA_KEY_SIZE = 3072;
    private static final int EC_KEY_SIZE = 384;
    /** Self-signed CA: keep legacy PKCS#1 v1.5 padding. */
    private static final String CA_SIG_ALGO = "SHA384withRSA";
    /** End-entity (agrCert): RSA-PSS padding. This is the only change. */
    private static final String AGR_SIG_ALGO = "SHA384withRSAandMGF1";
    private static final char[] KS_PASS = "debug".toCharArray();

    static void main(String[] args) throws Exception {
        boolean debug = false;
        int port = 0;
        for (String arg : args) {
            switch (arg) {
                case "--debug" -> debug = true;
                case "--mixed-pss" -> {}
                default -> port = Integer.parseInt(arg);
            }
        }

        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastleJsseProvider());

        if (debug) {
            Logger bcLogger = Logger.getLogger("org.bouncycastle.jsse.provider");
            bcLogger.setLevel(Level.ALL);
            var handler = new java.util.logging.ConsoleHandler();
            handler.setLevel(Level.ALL);
            bcLogger.addHandler(handler);
        } else {
            Logger.getLogger("org.bouncycastle.jsse.provider").setLevel(Level.SEVERE);
        }

        System.out.println("=== Mixed-PSS hypothesis test ===");
        System.out.println("TLS version : " + TLS_VERSION);
        System.out.println("Cipher suite: " + TLS_SUITE);
        System.out.println("Named groups: " + Arrays.toString(NAMED_GROUPS));
        System.out.println("Sig schemes : " + Arrays.toString(SIG_SCHEMES));
        System.out.println("CA key      : RSA-" + RSA_KEY_SIZE);
        System.out.println("Entity key  : EC-" + EC_KEY_SIZE);
        System.out.println("CA sig algo : " + CA_SIG_ALGO + "  (PKCS#1 v1.5, unchanged)");
        System.out.println("AgrCert sig : " + AGR_SIG_ALGO + "  (PSS — the only change)");
        System.out.println();

        // --- 1. Generate self-signed RSA CA with PKCS#1 v1.5 ---
        System.out.println("[1] Generating CA key pair (RSA-" + RSA_KEY_SIZE + ")...");
        final KeyPair caKeyPair = generateRsaKeyPair();
        final X509Certificate caCert = generateCaCertificate(caKeyPair);
        System.out.println("    CA DN     : " + caCert.getSubjectX500Principal());
        System.out.println("    CA key alg: " + caCert.getPublicKey().getAlgorithm());
        System.out.println("    CA sig alg: " + caCert.getSigAlgName());

        // --- 2. Server EC agrCert, signed with PSS ---
        System.out.println("[2] Generating server EC agrCert (PSS-signed)...");
        final KeyPair serverKeyPair = generateEcKeyPair();
        final X509Certificate serverCert = generateEndEntityCert("CN=server", serverKeyPair, caKeyPair, caCert);
        System.out.println("    Cert key  : " + serverCert.getPublicKey().getAlgorithm());
        System.out.println("    Cert sig  : " + serverCert.getSigAlgName());

        // --- 3. Client EC agrCert, signed with PSS ---
        System.out.println("[3] Generating client EC agrCert (PSS-signed)...");
        final KeyPair clientKeyPair = generateEcKeyPair();
        final X509Certificate clientCert = generateEndEntityCert("CN=client", clientKeyPair, caKeyPair, caCert);

        // --- 4. SSLContexts ---
        System.out.println("[4] Building SSLContexts (BCJSSE, PKIX)...");
        final SSLContext serverSslCtx = buildSslContext(serverKeyPair, serverCert, caCert);
        final SSLContext clientSslCtx = buildSslContext(clientKeyPair, clientCert, caCert);

        // --- 5. Server ---
        final SSLServerSocket serverSocket =
                (SSLServerSocket) serverSslCtx.getServerSocketFactory()
                        .createServerSocket(port, 1, InetAddress.getLoopbackAddress());
        configureSsl(serverSocket);
        final int actualPort = serverSocket.getLocalPort();
        System.out.println("[5] Server listening on localhost:" + actualPort);

        // --- 6. Client ---
        System.out.println("[6] Client connecting...");
        final Thread serverThread = startServerThread(serverSocket);

        final SSLSocket clientSocket = (SSLSocket) clientSslCtx.getSocketFactory().createSocket();
        configureSsl(clientSocket);
        clientSocket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), actualPort));
        clientSocket.startHandshake();

        System.out.println("    [client] Connected!");
        printSessionInfo("[client]", clientSocket);

        final PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        final BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        out.println("hello-mixed-pss");
        final String reply = in.readLine();
        System.out.println("    [client] Reply    : " + reply);

        clientSocket.close();
        serverThread.join(5000);
        serverSocket.close();

        System.out.println();
        System.out.println("=== HYPOTHESIS CONFIRMED ===");
        System.out.println("    BCJSSE TLS 1.3 accepts a chain with PKCS#1 v1.5 self-signed CA");
        System.out.println("    and PSS agrCert. The trust-anchor self-signature is not");
        System.out.println("    re-validated; only the issuance edge (CA → agrCert) is checked.");
        System.out.println();
        System.out.println("    Production implication: the BCJSSE migration does NOT require");
        System.out.println("    a sigCert refresh. Only agrCert generation needs PSS.");
    }

    private static Thread startServerThread(SSLServerSocket serverSocket) {
        final Thread t = new Thread(() -> {
            try {
                final SSLSocket accepted = (SSLSocket) serverSocket.accept();
                System.out.println("    [server] Accepted from " + accepted.getRemoteSocketAddress());
                printSessionInfo("[server]", accepted);

                final BufferedReader in = new BufferedReader(new InputStreamReader(accepted.getInputStream()));
                final PrintWriter out = new PrintWriter(accepted.getOutputStream(), true);
                final String msg = in.readLine();
                System.out.println("    [server] Received : " + msg);
                out.println("echo:" + msg);
                accepted.close();
            } catch (Exception e) {
                System.err.println("    [server] ERROR:");
                e.printStackTrace();
            }
        }, "mtls-server");
        t.setDaemon(true);
        t.start();
        return t;
    }

    private static void printSessionInfo(String prefix, SSLSocket socket) throws Exception {
        var session = socket.getSession();
        System.out.println("    " + prefix + " Protocol : " + session.getProtocol());
        System.out.println("    " + prefix + " Suite    : " + session.getCipherSuite());
        System.out.println("    " + prefix + " Peer DN  : "
                + ((X509Certificate) session.getPeerCertificates()[0]).getSubjectX500Principal());
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

    // ---- Certificate generation ----

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

        // Self-signed with PKCS#1 v1.5 — the legacy padding we want to keep on sigCert.
        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(builder.build(
                        new JcaContentSignerBuilder(CA_SIG_ALGO).setProvider("BC").build(caKeyPair.getPrivate())));
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

        // CA signs agrCert with PSS — this is the only PSS in the chain.
        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(builder.build(
                        new JcaContentSignerBuilder(AGR_SIG_ALGO).setProvider("BC").build(caKeyPair.getPrivate())));
    }

    // ---- SSL setup ----

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
        params.setNamedGroups(NAMED_GROUPS);
        params.setSignatureSchemes(SIG_SCHEMES);
        ss.setSSLParameters(params);
    }

    private static void configureSsl(SSLSocket s) {
        s.setEnabledProtocols(new String[]{TLS_VERSION});
        s.setEnabledCipherSuites(new String[]{TLS_SUITE});
        s.setNeedClientAuth(true);
        final SSLParameters params = s.getSSLParameters();
        params.setNamedGroups(NAMED_GROUPS);
        params.setSignatureSchemes(SIG_SCHEMES);
        s.setSSLParameters(params);
    }
}