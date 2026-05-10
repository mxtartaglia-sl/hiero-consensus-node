// SPDX-License-Identifier: Apache-2.0
package org.hiero.consensus.gossip.impl.network.connectivity;

import static java.util.Objects.requireNonNull;

import com.swirlds.config.api.Configuration;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import com.swirlds.logging.legacy.LogMarker;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.hiero.consensus.crypto.ConsensusCryptoUtils;
import org.hiero.consensus.crypto.CryptoConstants;
import org.hiero.consensus.exceptions.PlatformConstructionException;
import org.hiero.consensus.gossip.config.GossipConfig;
import org.hiero.consensus.gossip.config.SocketConfig;
import org.hiero.consensus.gossip.impl.gossip.Utilities;
import org.hiero.consensus.gossip.impl.network.PeerInfo;
import org.hiero.consensus.model.node.NodeId;

/**
 * used to create and receive TLS connections, based on the given trustStore
 */
public class TlsFactory implements SocketFactory {

    private static final Logger log = LogManager.getLogger(TlsFactory.class);

    private SSLServerSocketFactory sslServerSocketFactory;
    private SSLSocketFactory sslSocketFactory;

    private final Configuration configuration;
    private final NodeId selfId;
    private final SSLContext sslContext;
    private final SecureRandom nonDetRandom;
    private final KeyManagerFactory keyManagerFactory;
    private final TrustManagerFactory trustManagerFactory;

    /**
     * Construct this object to create and receive TLS connections.
     * @param agrCert the TLS certificate to use
     * @param sigCert the CA certificate that signed agrCert (for chain validation)
     * @param agrKey the private key corresponding to the public key in the certificate
     * @param peers the list of peers to allow connections with
     * @param selfId the id of this node
     * @param configuration configuration for the platform
     */
    public TlsFactory(
            @NonNull final Certificate agrCert,
            @NonNull final Certificate sigCert,
            @NonNull final PrivateKey agrKey,
            @NonNull final List<PeerInfo> peers,
            @NonNull final NodeId selfId,
            @NonNull final Configuration configuration)
            throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
        this.selfId = requireNonNull(selfId);
        this.configuration = requireNonNull(configuration);
        try {
            this.keyManagerFactory =
                    ConsensusCryptoUtils.createKeyManagerFactory(agrCert, sigCert, agrKey, configuration);
            this.trustManagerFactory = TrustManagerFactory.getInstance(
                    CryptoConstants.TRUST_MANAGER_FACTORY_TYPE, CryptoConstants.TRUST_MANAGER_FACTORY_PROVIDER);
            this.sslContext = SSLContext.getInstance(CryptoConstants.SSL_VERSION, CryptoConstants.SSL_PROVIDER);
        } catch (NoSuchProviderException e) {
            throw new PlatformConstructionException("BCJSSE provider not available", e);
        }
        this.nonDetRandom = ConsensusCryptoUtils.getNonDetRandom();

        reload(peers);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public @NonNull ServerSocket createServerSocket(final int port) throws IOException {
        final SSLServerSocket serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket();
        serverSocket.setEnabledProtocols(new String[] {CryptoConstants.SSL_VERSION});
        serverSocket.setEnabledCipherSuites(new String[] {CryptoConstants.TLS_SUITE});
        serverSocket.setWantClientAuth(true);
        serverSocket.setNeedClientAuth(true);
        final SSLParameters params = serverSocket.getSSLParameters();
        params.setNamedGroups(CryptoConstants.TLS_NAMED_GROUPS);
        params.setSignatureSchemes(CryptoConstants.TLS_SIGNATURE_SCHEMES);
        serverSocket.setSSLParameters(params);
        final SocketConfig socketConfig = configuration.getConfigData(SocketConfig.class);
        final GossipConfig gossipConfig = configuration.getConfigData(GossipConfig.class);
        SocketFactory.configureAndBind(selfId, serverSocket, socketConfig, gossipConfig, port);
        return serverSocket;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public @NonNull Socket createClientSocket(@NonNull final String hostname, final int port) throws IOException {
        requireNonNull(hostname);
        synchronized (this) {
            final SSLSocket clientSocket = (SSLSocket) sslSocketFactory.createSocket();
            // ensure the connection is ALWAYS the exact cipher suite we've chosen
            clientSocket.setEnabledProtocols(new String[] {CryptoConstants.SSL_VERSION});
            clientSocket.setEnabledCipherSuites(new String[] {CryptoConstants.TLS_SUITE});
            clientSocket.setWantClientAuth(true);
            clientSocket.setNeedClientAuth(true);
            final SSLParameters params = clientSocket.getSSLParameters();
            params.setNamedGroups(CryptoConstants.TLS_NAMED_GROUPS);
            params.setSignatureSchemes(CryptoConstants.TLS_SIGNATURE_SCHEMES);
            clientSocket.setSSLParameters(params);
            final SocketConfig socketConfig = configuration.getConfigData(SocketConfig.class);
            SocketFactory.configureAndConnect(clientSocket, socketConfig, hostname, port);
            clientSocket.startHandshake();
            logHandshake("client", clientSocket);
            return clientSocket;
        }
    }

    /** Call after handshake completes to log the negotiated TLS parameters. */
    public static void logHandshake(final String side, final SSLSocket socket) {
        try {
            final var session = socket.getSession();
            final String peerDn = session.getPeerCertificates().length > 0
                    ? ((java.security.cert.X509Certificate) session.getPeerCertificates()[0])
                      .getSubjectX500Principal()
                      .toString()
                    : "none";
            // Extract the negotiated named group via reflection on BCJSSE internals.
            // BCSSLConnection doesn't expose it publicly, but the TlsContext does.
            String namedGroup = extractNamedGroup(socket);
            log.info(
                    LogMarker.SOCKET_EXCEPTIONS.getMarker(),
                    "[TLS {}] protocol={} suite={} namedGroup={} peer={}",
                    side,
                    session.getProtocol(),
                    session.getCipherSuite(),
                    namedGroup,
                    peerDn);
        } catch (final Exception e) {
            log.warn(LogMarker.SOCKET_EXCEPTIONS.getMarker(), "[TLS {}] log failed: {}", side, e.getMessage());
        }
    }

    private static String extractNamedGroup(final SSLSocket socket) {
        try {
            if (!(socket instanceof org.bouncycastle.jsse.BCSSLSocket bcss)) {
                return "not-bcjsse";
            }
            final var conn = bcss.getConnection();
            if (conn == null) return "no-connection";
            // ProvSSLConnection has a protected `getTlsContext()` method
            java.lang.reflect.Method getTlsContext = null;
            Class<?> cls = conn.getClass();
            while (cls != null) {
                try {
                    getTlsContext = cls.getDeclaredMethod("getTlsContext");
                    break;
                } catch (NoSuchMethodException e) {
                    cls = cls.getSuperclass();
                }
            }
            if (getTlsContext == null) return "no-getTlsContext";
            getTlsContext.setAccessible(true);
            final Object ctx = getTlsContext.invoke(conn);
            if (ctx == null) return "null-context";
            // TlsContext.getSecurityParametersConnection() → SecurityParameters
            // Must use setAccessible because AbstractTlsContext is package-private in a named module
            final java.lang.reflect.Method getSp =
                    ctx.getClass().getMethod("getSecurityParametersConnection");
            getSp.setAccessible(true);
            final Object sp = getSp.invoke(ctx);
            if (sp == null) return "null-sp";
            // BC's SecurityParameters has no public getter for the *negotiated* TLS 1.3 named
            // group post-handshake — the value lives in private TlsAgreement state. We
            // reflectively read the `clientECPointFormats` / private fields to find a hint, but
            // the most reliable signal is the stored TlsKeyExchange or, failing that, scanning
            // declared fields for any int matching a known NamedGroup value.
            final StringBuilder sb = new StringBuilder();
            sb.append("negotiated=");
            sb.append(scanForNegotiatedGroup(sp));
            // Offered list (often empty post-handshake) — informational only.
            try {
                final java.lang.reflect.Method getClientGroups = sp.getClass().getMethod("getClientSupportedGroups");
                getClientGroups.setAccessible(true);
                final int[] clientGroups = (int[]) getClientGroups.invoke(sp);
                sb.append(" clientOffered=[");
                if (clientGroups != null) {
                    for (int i = 0; i < clientGroups.length; i++) {
                        if (i > 0) sb.append(",");
                        sb.append(org.bouncycastle.tls.NamedGroup.getText(clientGroups[i]));
                    }
                }
                sb.append("]");
            } catch (final NoSuchMethodException ignored) {
                /* ok */
            }
            return sb.toString();
        } catch (final Exception e) {
            return "extract-failed:" + e.getClass().getSimpleName() + ":" + e.getMessage();
        }
    }

    /**
     * Walks the TlsContext / SecurityParameters object graph looking for any int field that
     * matches a known TLS 1.3 NamedGroup. Returns a textual hint or "unknown" if no match.
     * <p>
     * BC stores the negotiated TLS 1.3 key share group in private fields of TlsAgreement
     * subclasses inside the TlsContext; there's no public getter. This walker is best-effort
     * and only used to confirm whether MLKEM768 or secp384r1 was selected during handshake.
     */
    private static String scanForNegotiatedGroup(final Object securityParameters) {
        try {
            // Scan TlsContext fields for any object whose class has a "namedGroup" int field
            // or that holds a KeyShareEntry. We resolve from the SecurityParameters' enclosing
            // TlsContext if reachable.
            final java.util.Set<Object> seen = new java.util.HashSet<>();
            final java.util.Deque<Object> stack = new java.util.ArrayDeque<>();
            stack.push(securityParameters);
            while (!stack.isEmpty()) {
                final Object o = stack.pop();
                if (o == null || !seen.add(o)) continue;
                if (seen.size() > 200) break;
                Class<?> cls = o.getClass();
                while (cls != null && cls != Object.class) {
                    for (final java.lang.reflect.Field f : cls.getDeclaredFields()) {
                        try {
                            f.setAccessible(true);
                            final Object v = f.get(o);
                            if (v == null) continue;
                            // Direct hit: a KeyShareEntry's namedGroup field
                            if (v.getClass().getName().endsWith("KeyShareEntry")) {
                                final java.lang.reflect.Method m = v.getClass().getMethod("getNamedGroup");
                                final int ng = (int) m.invoke(v);
                                return org.bouncycastle.tls.NamedGroup.getText(ng);
                            }
                            // int field literally named "namedGroup"
                            if (f.getType() == int.class && "namedGroup".equalsIgnoreCase(f.getName())) {
                                return org.bouncycastle.tls.NamedGroup.getText((int) v);
                            }
                            // Recurse only into BC TLS internal types (avoid noise).
                            if (v.getClass().getName().startsWith("org.bouncycastle.")) {
                                stack.push(v);
                            }
                        } catch (final Throwable t) {
                            /* ignore individual field probe failures */
                        }
                    }
                    cls = cls.getSuperclass();
                }
            }
            return "unknown";
        } catch (final Throwable t) {
            return "scan-failed:" + t.getClass().getSimpleName();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void reload(@NonNull final Collection<PeerInfo> peers) {
        try {
            synchronized (this) {
                // we just reset the list for now, until the work to calculate diffs is done
                // then, we will have two lists of peers to add and to remove
                final KeyStore signingTrustStore = Utilities.createPublicKeyStore(requireNonNull(peers));
                trustManagerFactory.init(signingTrustStore);
                sslContext.init(
                        keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), nonDetRandom);
                sslServerSocketFactory = sslContext.getServerSocketFactory();
                sslSocketFactory = sslContext.getSocketFactory();
            }
        } catch (final KeyStoreException | KeyManagementException e) {
            throw new PlatformConstructionException("A problem occurred while initializing the SocketFactory", e);
        }
    }
}
