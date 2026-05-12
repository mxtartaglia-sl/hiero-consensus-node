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
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * ML-KEM key exchange + EC (ECDSA) authentication using the <b>standard Java TLS stack</b> (SunJSSE).
 *
 * <p>Tests whether JDK's SunJSSE supports ML-KEM named groups for TLS 1.3
 * key exchange natively, with classical ECDSA for authentication.
 *
 * <p><b>Result (JDK 25):</b> FAILS. SunJSSE has ML-KEM at the JCA level (KEM, KeyFactory,
 * KeyPairGenerator) but silently ignores {@code X25519MLKEM768} in
 * {@code SSLParameters.setNamedGroups()} — logs "Ignore unspecified named group".
 * BCJSSE is required for ML-KEM key exchange in TLS 1.3.
 *
 * <p>Usage: {@code ./gradlew :consensus-tls-debug:run --args="--mlkem-java [--debug] [port]"}
 */
public final class MtlsDebugMlKemJava {

    private static final String TLS_VERSION = "TLSv1.3";
    private static final String TLS_SUITE = "TLS_AES_256_GCM_SHA384";
    private static final String KMF_TYPE = "SunX509";
    private static final String TMF_TYPE = "SunX509";
    private static final String KEYSTORE_TYPE = "pkcs12";
    private static final String CERT_SIG_ALGO = "SHA384withECDSA";
    private static final int EC_KEY_SIZE = 384;
    private static final char[] KS_PASS = "debug".toCharArray();

    static void main(String[] args) throws Exception {
        boolean debug = false;
        int port = 0;
        for (String arg : args) {
            switch (arg) {
                case "--debug" -> debug = true;
                case "--mlkem-java" -> {}
                default -> port = Integer.parseInt(arg);
            }
        }

        // BC only for cert generation
        Security.addProvider(new BouncyCastleProvider());

        if (debug) {
            System.setProperty("javax.net.debug", "ssl,handshake");
        }

        System.out.println("=== mTLS TLS 1.3 Debug Tool (Java SunJSSE + ML-KEM + ECDSA) ===");
        System.out.println("TLS version : " + TLS_VERSION);
        System.out.println("Cipher suite: " + TLS_SUITE);
        System.out.println("KMF/TMF     : " + KMF_TYPE + " / " + TMF_TYPE);
        System.out.println("Auth key    : EC-" + EC_KEY_SIZE);
        System.out.println("Cert sig    : " + CERT_SIG_ALGO);
        System.out.println();

        // Check what named groups SunJSSE supports
        final SSLContext probe = SSLContext.getInstance(TLS_VERSION);
        probe.init(null, null, null);
        final String[] defaultGroups = probe.getDefaultSSLParameters().getNamedGroups();
        System.out.println("SunJSSE default named groups: " + Arrays.toString(defaultGroups));
        System.out.println();

        // --- 1. Generate shared self-signed CA (EC) ---
        System.out.println("[1] Generating shared CA key pair (EC-" + EC_KEY_SIZE + ")...");
        final KeyPair caKeyPair = generateEcKeyPair();
        final X509Certificate caCert = generateCaCertificate(caKeyPair);
        System.out.println("    CA DN     : " + caCert.getSubjectX500Principal());

        // --- 2 & 3. Generate server/client keys + certs ---
        System.out.println("[2] Generating server EC key pair...");
        final KeyPair serverKeyPair = generateEcKeyPair();
        final X509Certificate serverCert = generateEndEntityCert("CN=server", serverKeyPair, caKeyPair, caCert);

        System.out.println("[3] Generating client EC key pair...");
        final KeyPair clientKeyPair = generateEcKeyPair();
        final X509Certificate clientCert = generateEndEntityCert("CN=client", clientKeyPair, caKeyPair, caCert);

        // --- 4. Build SSLContexts ---
        System.out.println("[4] Building SSLContexts (SunJSSE)...");
        final SSLContext serverSslCtx = buildSslContext(serverKeyPair, serverCert, caCert);
        final SSLContext clientSslCtx = buildSslContext(clientKeyPair, clientCert, caCert);
        System.out.println("    SSLContext provider: " + serverSslCtx.getProvider().getName());

        // Try to set ML-KEM named group
        final String[] namedGroups = {"X25519MLKEM768"};
        System.out.println("    Requesting named groups: " + Arrays.toString(namedGroups));

        // --- 5. Start server ---
        final SSLServerSocket serverSocket =
                (SSLServerSocket) serverSslCtx.getServerSocketFactory()
                        .createServerSocket(port, 1, InetAddress.getLoopbackAddress());
        configureSsl(serverSocket, namedGroups);
        final int actualPort = serverSocket.getLocalPort();
        System.out.println("[5] Server listening on localhost:" + actualPort);

        // Verify what actually got set
        final String[] actualGroups = serverSocket.getSSLParameters().getNamedGroups();
        System.out.println("    Actual named groups: " + Arrays.toString(actualGroups));

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
        out.println("hello-mlkem-java");
        final String reply = in.readLine();
        System.out.println("    [client] Reply    : " + reply);

        clientSocket.close();
        serverThread.join(5000);
        serverSocket.close();

        System.out.println();
        System.out.println("=== SUCCESS: mTLS TLS 1.3 + ML-KEM completed (Java SunJSSE) ===");
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
        final KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        keyStore.load(null, KS_PASS);
        keyStore.setKeyEntry("key", entityKeyPair.getPrivate(), KS_PASS,
                new java.security.cert.Certificate[]{entityCert, caCert});

        final KeyStore trustStore = KeyStore.getInstance(KEYSTORE_TYPE);
        trustStore.load(null, KS_PASS);
        trustStore.setCertificateEntry("ca", caCert);

        final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KMF_TYPE);
        kmf.init(keyStore, KS_PASS);

        final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TMF_TYPE);
        tmf.init(trustStore);

        final SSLContext ctx = SSLContext.getInstance(TLS_VERSION);
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), SecureRandom.getInstanceStrong());
        return ctx;
    }

    private static void configureSsl(SSLServerSocket ss, String[] namedGroups) {
        ss.setEnabledProtocols(new String[]{TLS_VERSION});
        ss.setEnabledCipherSuites(new String[]{TLS_SUITE});
        ss.setNeedClientAuth(true);
        final SSLParameters params = ss.getSSLParameters();
        params.setNamedGroups(namedGroups);
        ss.setSSLParameters(params);
    }

    private static void configureSsl(SSLSocket s, String[] namedGroups) {
        s.setEnabledProtocols(new String[]{TLS_VERSION});
        s.setEnabledCipherSuites(new String[]{TLS_SUITE});
        s.setNeedClientAuth(true);
        final SSLParameters params = s.getSSLParameters();
        params.setNamedGroups(namedGroups);
        s.setSSLParameters(params);
    }
}