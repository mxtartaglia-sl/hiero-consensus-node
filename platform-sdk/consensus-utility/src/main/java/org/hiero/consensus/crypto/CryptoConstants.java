// SPDX-License-Identifier: Apache-2.0
package org.hiero.consensus.crypto;

import java.security.Provider;
import java.security.Security;
import java.time.Instant;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

public final class CryptoConstants {
    // number of bytes in a hash
    public static final int HASH_SIZE_BYTES = 48; // 384 bits (= 3*128)
    // size (in bits) of a public or private key
    public static final int SIG_KEY_SIZE_BITS = 3072;
    public static final int AGR_KEY_SIZE_BITS = 384; // 3*128 bits
    // max number of bytes in a signature
    public static final int SIG_SIZE_BYTES = 384;
    // size of each symmetric key, in bytes
    public static final int SYM_KEY_SIZE_BYTES = 32; // 256 bits
    // the algorithms and providers to use (AGR is key agreement, SIG is signatures)
    public static final String AGR_TYPE = "ML-DSA-65";
    public static final String SIG_TYPE1 = "RSA";
    public static final String SIG_PROVIDER = getBCProviderName();
    public static final String AGR_PROVIDER = SIG_PROVIDER;
    public static final String SIG_TYPE2 = "SHA384withRSA";
    /** this is the only TLS protocol we will allow */
    public static final String TLS_SUITE = "TLS_AES_256_GCM_SHA384";
    // certificate settings
    public static final Instant DEFAULT_VALID_FROM = Instant.parse("2000-01-01T00:00:00Z");
    public static final Instant DEFAULT_VALID_TO = Instant.parse("2100-01-01T00:00:00Z");
    // SSL settings
    public static final String KEY_MANAGER_FACTORY_TYPE = "PKIX";
    public static final String KEY_MANAGER_FACTORY_PROVIDER = "BCJSSE";
    public static final String TRUST_MANAGER_FACTORY_TYPE = "PKIX";
    public static final String TRUST_MANAGER_FACTORY_PROVIDER = "BCJSSE";
    public static final String SSL_VERSION = "TLSv1.3";
    public static final String SSL_PROVIDER = "BCJSSE";
    public static final String[] TLS_NAMED_GROUPS = {"X25519MLKEM768,", "secp384r1"};
    public static final String[] TLS_SIGNATURE_SCHEMES = {
            "mldsa65",
            "mldsa44",
            "mldsa87",
            "ecdsa_secp384r1_sha384",
            "ecdsa_secp256r1_sha256",
            "ed25519",
            "ed448",
            "rsa_pss_rsae_sha256",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384"
    };
    // keystore settings
    public static final String KEYSTORE_TYPE = "BKS";
    public static final String KEYSTORE_PROVIDER = "BC";

    private CryptoConstants() {}

    /**
     * Installs the JCA providers this module depends on and returns the BouncyCastle provider
     * name so callers can refer to it by string.
     * <p>
     * Provider chain after this call:
     * <ol>
     *   <li>ACCP (position 1, if on classpath) — accelerates AES-GCM, HMAC, SHA-*, RSA-PSS,
     *       ECDSA, Ed25519, ML-DSA via AWS-LC.</li>
     *   <li>BouncyCastle — provides ML-KEM, cert builder, keystore, and every algorithm ACCP
     *       does not implement.</li>
     *   <li>BCJSSE configured with a custom {@link JcaTlsCryptoProvider} that uses a
     *       {@link HybridJcaJceHelper}: ML-KEM lookups go directly to BC (so BCJSSE's
     *       {@code KemUtil.isKemSupported} doesn't fail on a foreign provider's KPG that
     *       rejects BC's {@code MLKEMParameterSpec}); every other JCA lookup walks the global
     *       chain so ACCP at position 1 wins for AES-GCM / HMAC / SHA / RSA-PSS / ECDSA /
     *       Ed25519 / ML-DSA.</li>
     * </ol>
     */
    private static String getBCProviderName() {
        final boolean accpAvailable = registerAccpAtPosition1IfAvailable();
        final BouncyCastleProvider bcProv = new BouncyCastleProvider();
        Security.addProvider(bcProv);

        // Hybrid helper: ML-KEM → BC pinned; everything else → walks JCA chain when ACCP is
        // available (so ACCP at position 1 intercepts), or → BC pinned otherwise (so we don't
        // accidentally fall through to SunJCE/SunRsaSign in non-ACCP environments).
        final JcaJceHelper chainLeg =
                accpAvailable ? new DefaultJcaJceHelper() : new ProviderJcaJceHelper(bcProv);
        final JcaJceHelper hybridHelper = new HybridJcaJceHelper(new ProviderJcaJceHelper(bcProv), chainLeg);
        final JcaTlsCryptoProvider cryptoProvider = new JcaTlsCryptoProvider() {
            @Override
            public JcaJceHelper getHelper() {
                return hybridHelper;
            }
        };
        Security.addProvider(new BouncyCastleJsseProvider(false, cryptoProvider));

        return BouncyCastleProvider.PROVIDER_NAME;
    }

    /**
     * Registers ACCP at position 1 of the JCA provider chain via reflection, so non-TLS
     * consumers ({@code Signature.getInstance(alg)} without an explicit provider) also pick
     * it up. Returns {@code true} when ACCP was registered, {@code false} when ACCP is not on
     * the classpath (caller can use this to fall back to BC-pinned routing in the hybrid
     * helper's "chain" leg).
     */
    private static boolean registerAccpAtPosition1IfAvailable() {
        try {
            final Class<?> accpClass = Class.forName(
                    "com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider");
            final Provider accp = (Provider) accpClass.getField("INSTANCE").get(null);
            Security.insertProviderAt(accp, 1);
            return true;
        } catch (final Throwable ignored) {
            return false;
        }
    }
}