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
 * mTLS TLS 1.3 debug tool using the <b>standard Java TLS stack</b> (SunJSSE).
 *
 * <p>Replicates the same approach the gossip layer uses for TLS (SunX509 KMF/TMF,
 * PKCS12 keystore, EC agreement keys, self-signed certs signed by a shared RSA CA),
 * but upgraded from TLS 1.2 to TLS 1.3.
 *
 * <p>Gossip original (TLS 1.2):
 * <ul>
 *   <li>KMF/TMF: SunX509</li>
 *   <li>KeyStore: PKCS12</li>
 *   <li>SSLContext: TLSv1.2</li>
 *   <li>Suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384</li>
 *   <li>Key: EC-384 agreement key, cert signed by RSA-3072 signing key</li>
 * </ul>
 *
 * <p>This tool (TLS 1.3):
 * <ul>
 *   <li>KMF/TMF: SunX509 (same as gossip)</li>
 *   <li>KeyStore: PKCS12 (same as gossip)</li>
 *   <li>SSLContext: TLSv1.3</li>
 *   <li>Suite: TLS_AES_256_GCM_SHA384</li>
 *   <li>Key: EC-384 agreement key, cert signed by RSA-3072 signing key (same as gossip)</li>
 * </ul>
 *
 * <p>Usage: {@code ./gradlew :consensus-tls-debug:run --args="--java [--debug] [port]"}
 */
public final class MtlsDebugJava {

    private static final String TLS_VERSION = "TLSv1.3";
    private static final String TLS_SUITE = "TLS_AES_256_GCM_SHA384";
    // Gossip uses SunX509 for both KMF and TMF
    private static final String KMF_TYPE = "SunX509";
    private static final String TMF_TYPE = "SunX509";
    private static final String KEYSTORE_TYPE = "pkcs12";
    // Key sizes matching gossip: RSA-3072 for signing, EC-384 for agreement
    private static final int RSA_KEY_SIZE = 3072;
    private static final int EC_KEY_SIZE = 384;
    private static final String RSA_SIG_ALGO = "SHA384withRSA";
    private static final char[] KS_PASS = "debug".toCharArray();

    static void main(String[] args) throws Exception {
        boolean debug = false;
        boolean corrupt = false;
        int port = 0;
        for (String arg : args) {
            if ("--debug".equals(arg)) {
                debug = true;
            } else if ("--corrupt".equals(arg)) {
                corrupt = true;
            } else if (!"--java".equals(arg)) {
                port = Integer.parseInt(arg);
            }
        }

        // BC only needed for cert generation, NOT for TLS
        java.security.Security.addProvider(new BouncyCastleProvider());

        if (debug) {
            System.setProperty("javax.net.debug", "ssl,handshake");
        }

        System.out.println("=== mTLS TLS 1.3 Debug Tool (Java SunJSSE — gossip-style) ===");
        System.out.println("TLS version : " + TLS_VERSION);
        System.out.println("Cipher suite: " + TLS_SUITE);
        System.out.println("KMF/TMF     : " + KMF_TYPE + " / " + TMF_TYPE);
        System.out.println("KeyStore    : " + KEYSTORE_TYPE);
        System.out.println("CA key      : RSA-" + RSA_KEY_SIZE);
        System.out.println("Entity key  : EC-" + EC_KEY_SIZE);
        System.out.println("Cert sig    : " + RSA_SIG_ALGO);
        System.out.println();

        // --- 1. Generate shared self-signed CA (RSA, same as gossip signing key) ---
        System.out.println("[1] Generating shared CA key pair (RSA-" + RSA_KEY_SIZE + ")...");
        final KeyPair caKeyPair = generateRsaKeyPair();
        final X509Certificate caCert = generateCaCertificate(caKeyPair);
        System.out.println("    CA DN     : " + caCert.getSubjectX500Principal());

        // --- 2. Generate server agreement key + cert (EC, signed by RSA CA) ---
        System.out.println("[2] Generating server EC agreement key pair (EC-" + EC_KEY_SIZE + ")...");
        final KeyPair serverKeyPair = generateEcKeyPair();
        X509Certificate serverCert = generateEndEntityCert("CN=server", serverKeyPair, caKeyPair, caCert);
        if (corrupt) {
            System.out.println("    !!! Corrupting server cert signature !!!");
            serverCert = corruptSignature(serverCert);
        }
        System.out.println("    Server DN : " + serverCert.getSubjectX500Principal());
        System.out.println("    Cert sig  : " + serverCert.getSigAlgName());

        // --- 3. Generate client agreement key + cert (EC, signed by RSA CA) ---
        System.out.println("[3] Generating client EC agreement key pair (EC-" + EC_KEY_SIZE + ")...");
        final KeyPair clientKeyPair = generateEcKeyPair();
        X509Certificate clientCert = generateEndEntityCert("CN=client", clientKeyPair, caKeyPair, caCert);
        if (corrupt) {
            System.out.println("    !!! Corrupting client cert signature !!!");
            clientCert = corruptSignature(clientCert);
        }
        System.out.println("    Client DN : " + clientCert.getSubjectX500Principal());

        // --- 4. Build SSLContexts (standard Java, no BCJSSE) ---
        System.out.println("[4] Building SSLContexts (SunJSSE, SunX509)...");
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
        out.println("hello-mtls");
        final String reply = in.readLine();
        System.out.println("    [client] Reply    : " + reply);

        clientSocket.close();
        serverThread.join(5000);
        serverSocket.close();

        System.out.println();
        System.out.println("=== SUCCESS: mTLS TLS 1.3 handshake completed (Java SunJSSE) ===");
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
        // Show how many certs the PEER actually sent over the wire
        final var peerCerts = socket.getSession().getPeerCertificates();
        System.out.println("    " + prefix + " Peer sent " + peerCerts.length + " cert(s) in chain:");
        for (int i = 0; i < peerCerts.length; i++) {
            final var c = (X509Certificate) peerCerts[i];
            System.out.println("    " + prefix + "   [" + i + "] subject=" + c.getSubjectX500Principal()
                    + " issuer=" + c.getIssuerX500Principal());
        }
        var session = socket.getSession();
        System.out.println("    " + prefix + " Protocol : " + session.getProtocol());
        System.out.println("    " + prefix + " Suite    : " + session.getCipherSuite());
        System.out.println("    " + prefix + " Peer DN  : "
                + ((X509Certificate) session.getPeerCertificates()[0]).getSubjectX500Principal());
    }

    // ---- Cert corruption (for demonstrating signature verification) ----

    /**
     * Flips a byte in the cert's signature area (the last few bytes of the DER encoding),
     * then re-parses. Produces a cert that is structurally valid but whose signature
     * will fail verification against the CA's public key.
     */
    private static X509Certificate corruptSignature(X509Certificate cert) throws Exception {
        final byte[] der = cert.getEncoded();
        // The signature value is in the last ~384 bytes (for RSA-3072). Flipping a byte
        // in the last 10 bytes reliably hits the signature BIT STRING content.
        der[der.length - 5] ^= (byte) 0xFF;
        final var factory = java.security.cert.CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new java.io.ByteArrayInputStream(der));
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

    // ---- Certificate generation (using BC, same as gossip's CertificateUtils) ----

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
                        new JcaContentSignerBuilder(RSA_SIG_ALGO).setProvider("BC").build(caKeyPair.getPrivate())));
    }

    private static X509Certificate generateEndEntityCert(
            String dn, KeyPair entityKeyPair, KeyPair caKeyPair, X509Certificate caCert) throws Exception {
        final Date notBefore = Date.from(java.time.Instant.parse("2000-01-01T00:00:00Z"));
        final Date notAfter = Date.from(java.time.Instant.parse("2100-01-01T00:00:00Z"));

        // Exactly like gossip CertificateUtils.generateCertificate:
        //   - entity has EC key, CA has RSA key
        //   - cert signed by CA's RSA key with SHA384withRSA
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
                        new JcaContentSignerBuilder(RSA_SIG_ALGO).setProvider("BC").build(caKeyPair.getPrivate())));
    }

    // ---- SSL setup (standard Java, same pattern as gossip TlsFactory) ----

    private static SSLContext buildSslContext(
            KeyPair entityKeyPair, X509Certificate entityCert, X509Certificate caCert) throws Exception {
        // Key store: PKCS12, entity private key + ONLY the end-entity cert (exactly like gossip main).
        // The sigCert (CA) is NOT in the keystore chain — SunJSSE's PKIX path builder will
        // reconstruct the chain at validation time using the peer's trust store.
        final KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);





        keyStore.load(null, KS_PASS);
        keyStore.setKeyEntry("key", entityKeyPair.getPrivate(), KS_PASS,
                new java.security.cert.Certificate[]{entityCert});

        // Trust store: PKCS12, CA cert (gossip uses signing certs of peers)
        final KeyStore trustStore = KeyStore.getInstance(KEYSTORE_TYPE);
        trustStore.load(null, KS_PASS);
        trustStore.setCertificateEntry("ca", caCert);

        // SunX509 KMF — same as gossip's ConsensusCryptoUtils.createKeyManagerFactory
        final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KMF_TYPE);
        kmf.init(keyStore, KS_PASS);

        // SunX509 TMF — same as gossip's TlsFactory constructor
        final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TMF_TYPE);
        tmf.init(trustStore);





        // Standard Java SSLContext (SunJSSE), NOT BCJSSE
        final SSLContext ctx = SSLContext.getInstance(TLS_VERSION);
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), SecureRandom.getInstanceStrong());
        return ctx;
    }

    // Gossip-style socket configuration, upgraded to TLS 1.3
    private static void configureSslServer(SSLServerSocket ss) {
        ss.setEnabledProtocols(new String[]{TLS_VERSION});
        ss.setEnabledCipherSuites(new String[]{TLS_SUITE});
        ss.setWantClientAuth(true);
        ss.setNeedClientAuth(true);
    }

    private static void configureSslClient(SSLSocket s) {
        s.setEnabledProtocols(new String[]{TLS_VERSION});
        s.setEnabledCipherSuites(new String[]{TLS_SUITE});
        s.setWantClientAuth(true);
        s.setNeedClientAuth(true);
    }
}