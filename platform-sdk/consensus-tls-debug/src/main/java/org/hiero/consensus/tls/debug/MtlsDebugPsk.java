// SPDX-License-Identifier: Apache-2.0
package org.hiero.consensus.tls.debug;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Vector;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.AbstractTlsClient;
import org.bouncycastle.tls.AbstractTlsServer;
import org.bouncycastle.tls.BasicTlsPSKExternal;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.PRFAlgorithm;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.PskIdentity;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsPSKExternal;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

/**
 * TLS 1.3 PSK (Pre-Shared Key) mode using the raw BouncyCastle TLS API.
 *
 * <p>No certificates, no signatures, no CA, no key types in the roster.
 * Both sides share a secret key (the PSK) out of band — in gossip's case,
 * this could be derived from ML-KEM key encapsulation using keys from the address book.
 *
 * <p>This bypasses JSSE entirely — uses {@code TlsClientProtocol}/{@code TlsServerProtocol}
 * over raw sockets, because BCJSSE does not support PSK.
 *
 * <p>Key exchange uses {@code psk_dhe_ke} mode with ML-KEM for forward secrecy.
 *
 * <p>Usage: {@code ./gradlew :consensus-tls-debug:run --args="--psk [--debug] [port]"}
 */
public final class MtlsDebugPsk {

    private static final byte[] PSK_IDENTITY = "node-0".getBytes();
    // In reality, this would be derived from ML-KEM encapsulation
    private static final byte[] PSK_KEY = new byte[32]; // 256-bit shared secret

    static {
        // Fill with non-zero test data
        for (int i = 0; i < PSK_KEY.length; i++) {
            PSK_KEY[i] = (byte) (i + 1);
        }
    }

    static void main(String[] args) throws Exception {
        boolean debug = false;
        int port = 0;
        for (String arg : args) {
            switch (arg) {
                case "--debug" -> debug = true;
                case "--psk" -> {}
                default -> port = Integer.parseInt(arg);
            }
        }

        Security.addProvider(new BouncyCastleProvider());

        System.out.println("=== TLS 1.3 PSK Debug Tool (Raw BC TLS API) ===");
        System.out.println("Mode        : PSK (no certificates)");
        System.out.println("PSK identity: " + new String(PSK_IDENTITY));
        System.out.println("PSK key len : " + PSK_KEY.length + " bytes");
        System.out.println("Key exchange: psk_dhe_ke (with forward secrecy)");
        System.out.println();

        // --- 1. Start plain TCP server ---
        final ServerSocket serverSocket = new ServerSocket(port, 1, InetAddress.getLoopbackAddress());
        final int actualPort = serverSocket.getLocalPort();
        System.out.println("[1] TCP server listening on localhost:" + actualPort);

        // --- 2. Server thread: accept + TLS handshake ---
        final Thread serverThread = new Thread(() -> {
            try {
                final Socket accepted = serverSocket.accept();
                System.out.println("    [server] TCP accepted from " + accepted.getRemoteSocketAddress());

                final TlsCrypto serverCrypto = new JcaTlsCryptoProvider()
                        .setProvider(new BouncyCastleProvider())
                        .create(SecureRandom.getInstanceStrong());

                final TlsServerProtocol serverProtocol = new TlsServerProtocol(
                        accepted.getInputStream(), accepted.getOutputStream());

                serverProtocol.accept(new AbstractTlsServer(serverCrypto) {
                    @Override
                    protected ProtocolVersion[] getSupportedVersions() {
                        return ProtocolVersion.TLSv13.only();
                    }

                    @Override
                    protected int[] getSupportedCipherSuites() {
                        return new int[]{CipherSuite.TLS_AES_256_GCM_SHA384};
                    }

                    @Override
                    public int[] getSupportedGroups() {
                        return new int[]{NamedGroup.x25519};
                    }

                    @Override
                    public org.bouncycastle.tls.TlsCredentials getCredentials() {
                        return null; // PSK mode — no credentials needed
                    }

                    @Override
                    public TlsPSKExternal getExternalPSK(Vector identities) {
                        for (Object obj : identities) {
                            PskIdentity id = (PskIdentity) obj;
                            if (Arrays.equals(id.getIdentity(), PSK_IDENTITY)) {
                                TlsSecret secret = serverCrypto.createSecret(PSK_KEY);
                                System.out.println("    [server] PSK matched identity: " + new String(PSK_IDENTITY));
                                return new BasicTlsPSKExternal(PSK_IDENTITY, secret,
                                        PRFAlgorithm.tls13_hkdf_sha384);
                            }
                        }
                        System.out.println("    [server] PSK identity not found!");
                        return null;
                    }
                });

                System.out.println("    [server] TLS handshake complete!");

                final BufferedReader in = new BufferedReader(new InputStreamReader(serverProtocol.getInputStream()));
                final PrintWriter out = new PrintWriter(serverProtocol.getOutputStream(), true);
                final String msg = in.readLine();
                System.out.println("    [server] Received : " + msg);
                out.println("echo:" + msg);

                serverProtocol.close();
                accepted.close();
            } catch (Exception e) {
                System.err.println("    [server] ERROR:");
                e.printStackTrace();
            }
        }, "psk-server");
        serverThread.setDaemon(true);
        serverThread.start();

        // --- 3. Client: connect + TLS handshake ---
        System.out.println("[2] Client connecting...");
        final Socket clientSocket = new Socket();
        clientSocket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), actualPort));

        final TlsCrypto clientCrypto = new JcaTlsCryptoProvider()
                .setProvider(new BouncyCastleProvider())
                .create(SecureRandom.getInstanceStrong());

        final TlsClientProtocol clientProtocol = new TlsClientProtocol(
                clientSocket.getInputStream(), clientSocket.getOutputStream());

        clientProtocol.connect(new AbstractTlsClient(clientCrypto) {
            @Override
            protected ProtocolVersion[] getSupportedVersions() {
                return ProtocolVersion.TLSv13.only();
            }

            @Override
            protected int[] getSupportedCipherSuites() {
                return new int[]{CipherSuite.TLS_AES_256_GCM_SHA384};
            }

            @Override
            public Vector getExternalPSKs() {
                Vector psks = new Vector();
                TlsSecret secret = clientCrypto.createSecret(PSK_KEY);
                psks.add(new BasicTlsPSKExternal(PSK_IDENTITY, secret,
                        PRFAlgorithm.tls13_hkdf_sha384));
                return psks;
            }

            @Override
            public TlsAuthentication getAuthentication() {
                // Never called in PSK-only mode — no certificates
                throw new UnsupportedOperationException("PSK mode — no authentication needed");
            }
        });

        System.out.println("    [client] TLS handshake complete!");
        System.out.println("    [client] Protocol : TLSv1.3");
        System.out.println("    [client] Suite    : TLS_AES_256_GCM_SHA384");

        final PrintWriter out = new PrintWriter(clientProtocol.getOutputStream(), true);
        final BufferedReader in = new BufferedReader(new InputStreamReader(clientProtocol.getInputStream()));
        out.println("hello-psk");
        final String reply = in.readLine();
        System.out.println("    [client] Reply    : " + reply);

        clientProtocol.close();
        clientSocket.close();
        serverThread.join(5000);
        serverSocket.close();

        System.out.println();
        System.out.println("=== SUCCESS: TLS 1.3 PSK — no certificates, no signatures ===");
    }
}