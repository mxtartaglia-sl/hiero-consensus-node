// SPDX-License-Identifier: Apache-2.0
package org.hiero.consensus.tls.debug;

import java.security.Security;
import java.util.Arrays;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

/**
 * Isolated test to confirm whether ECDH in jdk.tls.disabledAlgorithms
 * independently blocks ECDSA signature schemes in BCJSSE.
 *
 * Test: secp384r1 IS in named groups, ECDH is NOT patched.
 * If ECDSA is absent from signature_algorithms → ECDH disable confirmed.
 * If ECDSA is present → only named group gating was the blocker.
 */
public final class MtlsDebugEcdhTest {

    static void main(String[] args) throws Exception {
        // NO ECDH patching — this is the test
        System.out.println("=== ECDH Disable Isolation Test ===");
        System.out.println("ECDH patched: NO");
        System.out.println("secp384r1 in named groups: YES");
        System.out.println();

        String disabled = Security.getProperty("jdk.tls.disabledAlgorithms");
        System.out.println("jdk.tls.disabledAlgorithms contains ECDH: " + disabled.contains("ECDH"));
        System.out.println();

        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastleJsseProvider());

        // Enable debug to see signature_algorithms
        Logger bcLogger = Logger.getLogger("org.bouncycastle.jsse.provider");
        bcLogger.setLevel(Level.FINEST);
        ConsoleHandler handler = new ConsoleHandler();
        handler.setLevel(Level.FINEST);
        bcLogger.addHandler(handler);

        SSLContext ctx = SSLContext.getInstance("TLSv1.3", "BCJSSE");
        ctx.init(null, null, null);

        SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket();
        SSLParameters params = socket.getSSLParameters();
        params.setNamedGroups(new String[]{"x25519", "secp384r1"});
        params.setSignatureSchemes(new String[]{
                "ecdsa_secp384r1_sha384",
                "ecdsa_secp256r1_sha256",
                "ed25519",
                "rsa_pss_rsae_sha256",
        });
        socket.setSSLParameters(params);

        // Read back what BCJSSE actually kept
        SSLParameters verify = socket.getSSLParameters();
        System.out.println();
        System.out.println("=== RESULT ===");
        System.out.println("Requested sig schemes: [ecdsa_secp384r1_sha384, ecdsa_secp256r1_sha256, ed25519, rsa_pss_rsae_sha256]");
        System.out.println("Actual sig schemes   : " + Arrays.toString(verify.getSignatureSchemes()));
        System.out.println("Actual named groups  : " + Arrays.toString(verify.getNamedGroups()));

        String[] sigSchemes = verify.getSignatureSchemes();
        boolean hasEcdsa = false;
        if (sigSchemes != null) {
            for (String s : sigSchemes) {
                if (s.startsWith("ecdsa")) {
                    hasEcdsa = true;
                    break;
                }
            }
        }
        System.out.println();
        if (hasEcdsa) {
            System.out.println("CONCLUSION: ECDSA survived → ECDH disable does NOT independently block ECDSA");
            System.out.println("            Only named group gating (failure 2) was the real blocker");
        } else {
            System.out.println("CONCLUSION: ECDSA filtered out → ECDH disable CONFIRMED as independent blocker");
            System.out.println("            Both failure 1 (ECDH) and failure 2 (named groups) are real");
        }

        socket.close();
    }
}