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
 * Post-quantum mTLS TLS 1.3 debug tool using the <b>standard Java TLS stack</b> (SunJSSE)
 * with ML-DSA-65 for authentication.
 *
 * <p>Tests whether JDK's SunJSSE supports ML-DSA as a TLS 1.3 signature scheme
 * natively, without BouncyCastle JSSE.
 *
 * <p><b>Result (JDK 25):</b> FAILS. SunJSSE has ML-DSA at the JCA level
 * (KeyPairGenerator, Signature) but does NOT include mldsa44/65/87 in its
 * TLS 1.3 signature_algorithms extension. BCJSSE is required for PQ TLS.
 *
 * <ul>
 *   <li>SSLContext/KMF/TMF: standard Java (SunJSSE / SunX509)</li>
 *   <li>Key exchange: default SunJSSE (x25519/secp256r1/etc.)</li>
 *   <li>Authentication: ML-DSA-65 certificates</li>
 *   <li>Cert generation: BouncyCastle (for X.509 builder only)</li>
 * </ul>
 *
 * <p>Usage: {@code ./gradlew :consensus-tls-debug:run --args="--pq-java [--debug] [port]"}
 */
public final class MtlsDebugPqJava {

    private static final String TLS_VERSION = "TLSv1.3";
    private static final String TLS_SUITE = "TLS_AES_256_GCM_SHA384";
    private static final String KMF_TYPE = "SunX509";
    private static final String TMF_TYPE = "SunX509";
    private static final String KEYSTORE_TYPE = "pkcs12";
    private static final String CERT_KEY_ALGO = "ML-DSA-65";
    private static final String CERT_SIG_ALGO = "ML-DSA-65";
    private static final char[] KS_PASS = "debug".toCharArray();

    static void main(String[] args) throws Exception {
        boolean debug = false;
        int port = 0;
        for (String arg : args) {
            switch (arg) {
                case "--debug" -> debug = true;
                case "--pq-java" -> {}
                default -> port = Integer.parseInt(arg);
            }
        }

        // BC only needed for cert generation, NOT for TLS
        Security.addProvider(new BouncyCastleProvider());

        if (debug) {
            System.setProperty("javax.net.debug", "ssl,handshake");
        }

        System.out.println("=== mTLS TLS 1.3 Debug Tool (Java SunJSSE + ML-DSA) ===");
        System.out.println("TLS version : " + TLS_VERSION);
        System.out.println("Cipher suite: " + TLS_SUITE);
        System.out.println("KMF/TMF     : " + KMF_TYPE + " / " + TMF_TYPE);
        System.out.println("KeyStore    : " + KEYSTORE_TYPE);
        System.out.println("Auth key    : " + CERT_KEY_ALGO);
        System.out.println("Cert sig    : " + CERT_SIG_ALGO);
        System.out.println();

        // --- 1. Generate shared self-signed CA (ML-DSA-65) ---
        System.out.println("[1] Generating shared CA key pair (" + CERT_KEY_ALGO + ")...");
        final KeyPair caKeyPair = generateMlDsaKeyPair();
        final X509Certificate caCert = generateCaCertificate(caKeyPair);
        System.out.println("    CA DN     : " + caCert.getSubjectX500Principal());
        System.out.println("    CA key alg: " + caCert.getPublicKey().getAlgorithm());
        System.out.println("    CA sig alg: " + caCert.getSigAlgName());

        // --- 2. Generate server auth key + cert ---
        System.out.println("[2] Generating server auth key pair (" + CERT_KEY_ALGO + ")...");
        final KeyPair serverKeyPair = generateMlDsaKeyPair();
        final X509Certificate serverCert = generateEndEntityCert("CN=server", serverKeyPair, caKeyPair, caCert);
        System.out.println("    Server DN : " + serverCert.getSubjectX500Principal());

        // --- 3. Generate client auth key + cert ---
        System.out.println("[3] Generating client auth key pair (" + CERT_KEY_ALGO + ")...");
        final KeyPair clientKeyPair = generateMlDsaKeyPair();
        final X509Certificate clientCert = generateEndEntityCert("CN=client", clientKeyPair, caKeyPair, caCert);
        System.out.println("    Client DN : " + clientCert.getSubjectX500Principal());

        // --- 4. Build SSLContexts (standard Java, NO BCJSSE) ---
        System.out.println("[4] Building SSLContexts (SunJSSE)...");
        final SSLContext serverSslCtx = buildSslContext(serverKeyPair, serverCert, caCert);
        final SSLContext clientSslCtx = buildSslContext(clientKeyPair, clientCert, caCert);
        System.out.println("    SSLContext provider: " + serverSslCtx.getProvider().getName());

        // --- 5. Start server ---
        final SSLServerSocket serverSocket =
                (SSLServerSocket) serverSslCtx.getServerSocketFactory()
                        .createServerSocket(port, 1, InetAddress.getLoopbackAddress());
        configureSslServer(serverSocket);
        final int actualPort = serverSocket.getLocalPort();
        System.out.println("[5] Server listening on localhost:" + actualPort);
        System.out.println("    Enabled protocols: " + Arrays.toString(serverSocket.getEnabledProtocols()));
        System.out.println("    Enabled suites   : " + Arrays.toString(serverSocket.getEnabledCipherSuites()));

        // --- 6. Connect client ---
        System.out.println("[6] Client connecting...");
        final Thread serverThread = startServerThread(serverSocket);

        final SSLSocket clientSocket = (SSLSocket) clientSslCtx.getSocketFactory().createSocket();
        configureSslClient(clientSocket);
        clientSocket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), actualPort));
        clientSocket.startHandshake();

        System.out.println("    [client] Connected!");
        printSessionInfo("[client]", clientSocket);

        final PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        final BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        out.println("hello-pq-java");
        final String reply = in.readLine();
        System.out.println("    [client] Reply    : " + reply);

        clientSocket.close();
        serverThread.join(5000);
        serverSocket.close();

        System.out.println();
        System.out.println("=== SUCCESS: mTLS TLS 1.3 + ML-DSA completed (Java SunJSSE) ===");
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
        // Use BC for key generation — BC's keys are compatible with BC's ContentSignerBuilder
        // for cert generation, and SunJSSE can still use them for TLS via PKCS12 keystore
        final KeyPairGenerator gen = KeyPairGenerator.getInstance(CERT_KEY_ALGO, "BC");
        return gen.generateKeyPair();
    }

    // ---- Certificate generation (BC for X.509 builder, JDK keys) ----

    private static X509Certificate generateCaCertificate(KeyPair caKeyPair) throws Exception {
        final Date notBefore = Date.from(java.time.Instant.parse("2000-01-01T00:00:00Z"));
        final Date notAfter = Date.from(java.time.Instant.parse("2100-01-01T00:00:00Z"));

        final X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Principal("CN=DebugCA-PQ-Java"),
                BigInteger.valueOf(1),
                notBefore, notAfter,
                new X500Principal("CN=DebugCA-PQ-Java"),
                caKeyPair.getPublic());

        builder.addExtension(Extension.subjectKeyIdentifier, false,
                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(caKeyPair.getPublic()));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        // Use BC's ContentSignerBuilder — it knows how to sign with ML-DSA keys
        return new JcaX509CertificateConverter()
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
                .getCertificate(builder.build(
                        new JcaContentSignerBuilder(CERT_SIG_ALGO).setProvider("BC").build(caKeyPair.getPrivate())));
    }

    // ---- SSL setup (standard Java, gossip-style) ----

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

        // Standard Java SSLContext (SunJSSE)
        final SSLContext ctx = SSLContext.getInstance(TLS_VERSION);
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), SecureRandom.getInstanceStrong());
        return ctx;
    }

    private static final String[] SIG_SCHEMES = {
            "mldsa65", "mldsa44", "mldsa87",
            "ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384",
            "ed25519", "ed448",
            "rsa_pss_rsae_sha256", "rsa_pss_rsae_sha384",
    };

    private static void configureSslServer(SSLServerSocket ss) {
        ss.setEnabledProtocols(new String[]{TLS_VERSION});
        ss.setEnabledCipherSuites(new String[]{TLS_SUITE});
        ss.setWantClientAuth(true);
        ss.setNeedClientAuth(true);
        final SSLParameters params = ss.getSSLParameters();
        params.setSignatureSchemes(SIG_SCHEMES);
        ss.setSSLParameters(params);
        // Verify what SunJSSE actually accepted
        System.out.println("    [server] sigSchemes set: " + Arrays.toString(
                ss.getSSLParameters().getSignatureSchemes()));
    }

    private static void configureSslClient(SSLSocket s) {
        s.setEnabledProtocols(new String[]{TLS_VERSION});
        s.setEnabledCipherSuites(new String[]{TLS_SUITE});
        s.setWantClientAuth(true);
        s.setNeedClientAuth(true);
        final SSLParameters params = s.getSSLParameters();
        params.setSignatureSchemes(SIG_SCHEMES);
        s.setSSLParameters(params);
    }
}