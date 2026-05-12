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
import java.util.logging.ConsoleHandler;
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
 * Fully post-quantum mTLS TLS 1.3 debug tool using BouncyCastle JSSE.
 *
 * <ul>
 *   <li>Key exchange: <b>ML-KEM-768</b> (hybrid X25519MLKEM768 or pure MLKEM768)</li>
 *   <li>Authentication: <b>ML-DSA-65</b> (CRYSTALS-Dilithium) for certificates and CertificateVerify</li>
 *   <li>CA: self-signed ML-DSA-65</li>
 * </ul>
 *
 * <p>This is a fully post-quantum TLS 1.3 connection — both key exchange and
 * authentication use lattice-based PQ algorithms.
 *
 * <p>Usage: {@code ./gradlew :consensus-tls-debug:run --args="--pq [--debug] [--pure] [port]"}
 */
public final class MtlsDebugPq {

    private static final String TLS_VERSION = "TLSv1.3";
    private static final String TLS_SUITE = "TLS_AES_256_GCM_SHA384";

    private static final String NAMED_GROUP_HYBRID = "X25519MLKEM768";
    private static final String NAMED_GROUP_PURE = ""
                                                   + "";

    // ML-DSA signature schemes for TLS 1.3 (draft-ietf-tls-mldsa-00)
    // BCJSSE does NOT enable these by default — must be set explicitly
    private static final String[] SIG_SCHEMES = {
            "mldsa65",
            "mldsa44",
            "mldsa87",
    };

    // ML-DSA-65 for certificate generation (JCA algorithm name)
    private static final String CERT_KEY_ALGO = "ML-DSA-65";
    private static final String CERT_SIG_ALGO = "ML-DSA-65";
    private static final char[] KS_PASS = "debug".toCharArray();

    static void main(String[] args) throws Exception {
        boolean debug = false;
        boolean pure = false;
        int port = 0;
        for (String arg : args) {
            switch (arg) {
                case "--debug" -> debug = true;
                case "--pure" -> pure = true;
                case "--pq" -> {}
                default -> port = Integer.parseInt(arg);
            }
        }

        final String keyExchangeGroup = pure ? NAMED_GROUP_PURE : NAMED_GROUP_HYBRID;
        final String[] namedGroups = {keyExchangeGroup};

        // No ECDH patching needed — we don't use any EC signature schemes

        final BouncyCastleProvider bcProv = new BouncyCastleProvider();
        Security.addProvider(bcProv);
        // MUST pass BC provider explicitly so BCJSSE's JcaTlsCrypto uses BC for ML-KEM.
        // Without this, DefaultJcaJceHelper finds JDK 25's SunJCE ML-KEM implementation
        // which rejects BC's MLKEMParameterSpec, causing KemUtil.isKemSupported() to fail.
        Security.addProvider(new BouncyCastleJsseProvider(bcProv));

        if (debug) {
            enableBcjsseDebugLogging();
        } else {
            Logger.getLogger("org.bouncycastle.jsse.provider").setLevel(Level.SEVERE);
        }

        System.out.println("=== mTLS TLS 1.3 Debug Tool (Fully Post-Quantum) ===");
        System.out.println("TLS version : " + TLS_VERSION);
        System.out.println("Cipher suite: " + TLS_SUITE);
        System.out.println("Key exchange: " + keyExchangeGroup + (pure ? " (pure PQ)" : " (hybrid)"));
        System.out.println("Named groups: " + Arrays.toString(namedGroups));
        System.out.println("Auth key    : " + CERT_KEY_ALGO);
        System.out.println("Sig schemes : " + Arrays.toString(SIG_SCHEMES));
        System.out.println("Cert sig    : " + CERT_SIG_ALGO);
        System.out.println();

        // --- 1. Generate shared self-signed CA (ML-DSA-65) ---
        System.out.println("[1] Generating shared CA key pair (" + CERT_KEY_ALGO + ")...");
        final KeyPair caKeyPair = generateMlDsaKeyPair();
        final X509Certificate caCert = generateCaCertificate(caKeyPair);
        System.out.println("    CA DN     : " + caCert.getSubjectX500Principal());
        System.out.println("    CA key alg: " + caCert.getPublicKey().getAlgorithm());
        System.out.println("    CA sig alg: " + caCert.getSigAlgName());

        // --- 2. Generate server auth key + cert (ML-DSA-65) ---
        System.out.println("[2] Generating server auth key pair (" + CERT_KEY_ALGO + ")...");
        final KeyPair serverKeyPair = generateMlDsaKeyPair();
        final X509Certificate serverCert = generateEndEntityCert("CN=server", serverKeyPair, caKeyPair, caCert);
        System.out.println("    Server DN : " + serverCert.getSubjectX500Principal());

        // --- 3. Generate client auth key + cert (ML-DSA-65) ---
        System.out.println("[3] Generating client auth key pair (" + CERT_KEY_ALGO + ")...");
        final KeyPair clientKeyPair = generateMlDsaKeyPair();
        final X509Certificate clientCert = generateEndEntityCert("CN=client", clientKeyPair, caKeyPair, caCert);
        System.out.println("    Client DN : " + clientCert.getSubjectX500Principal());

        // --- 4. Build SSLContexts ---
        System.out.println("[4] Building SSLContexts (BCJSSE, PKIX)...");
        final SSLContext serverSslCtx = buildSslContext(serverKeyPair, serverCert, caCert);
        final SSLContext clientSslCtx = buildSslContext(clientKeyPair, clientCert, caCert);

        // --- 5. Start server ---
        final SSLServerSocket serverSocket =
                (SSLServerSocket) serverSslCtx.getServerSocketFactory()
                        .createServerSocket(port, 1, InetAddress.getLoopbackAddress());
        configureSsl(serverSocket, namedGroups);
        final int actualPort = serverSocket.getLocalPort();
        System.out.println("[5] Server listening on localhost:" + actualPort);

        // --- 6. Connect client ---
        System.out.println("[6] Client connecting...");
        final Thread serverThread = startServerThread(serverSocket);

        final SSLSocket clientSocket = (SSLSocket) clientSslCtx.getSocketFactory().createSocket();
        configureSsl(clientSocket, namedGroups);
        clientSocket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), actualPort));
        clientSocket.startHandshake();

        System.out.println("    [client] Connected!");
        printSessionInfo("[client]", clientSocket);

        final PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        final BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        out.println("hello-pq");
        final String reply = in.readLine();
        System.out.println("    [client] Reply    : " + reply);

        clientSocket.close();
        serverThread.join(5000);
        serverSocket.close();

        System.out.println();
        System.out.println("=== SUCCESS: Fully post-quantum mTLS TLS 1.3 handshake completed ===");
        System.out.println("    Key exchange : " + keyExchangeGroup);
        System.out.println("    Authentication: " + CERT_KEY_ALGO);
    }

    // ---- Server accept thread ----

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

    private static KeyPair generateMlDsaKeyPair() throws Exception {
        final KeyPairGenerator gen = KeyPairGenerator.getInstance(CERT_KEY_ALGO, "BC");
        return gen.generateKeyPair();
    }

    // ---- Certificate generation ----

    private static X509Certificate generateCaCertificate(KeyPair caKeyPair) throws Exception {
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
                new KeyUsage(KeyUsage.digitalSignature));
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

    private static void configureSsl(SSLServerSocket ss, String[] namedGroups) {
        ss.setEnabledProtocols(new String[]{TLS_VERSION});
        ss.setEnabledCipherSuites(new String[]{TLS_SUITE});
        ss.setNeedClientAuth(true);
        final SSLParameters params = ss.getSSLParameters();
        params.setNamedGroups(namedGroups);
        params.setSignatureSchemes(SIG_SCHEMES);
        ss.setSSLParameters(params);
    }

    private static void configureSsl(SSLSocket s, String[] namedGroups) {
        s.setEnabledProtocols(new String[]{TLS_VERSION});
        s.setEnabledCipherSuites(new String[]{TLS_SUITE});
        s.setNeedClientAuth(true);
        final SSLParameters params = s.getSSLParameters();
        params.setNamedGroups(namedGroups);
        params.setSignatureSchemes(SIG_SCHEMES);
        s.setSSLParameters(params);
    }

    // ---- Debug logging ----

    private static void enableBcjsseDebugLogging() {
        Logger bcLogger = Logger.getLogger("org.bouncycastle.jsse.provider");
        bcLogger.setLevel(Level.ALL);
        ConsoleHandler handler = new ConsoleHandler();
        handler.setLevel(Level.ALL);
        bcLogger.addHandler(handler);
    }
}