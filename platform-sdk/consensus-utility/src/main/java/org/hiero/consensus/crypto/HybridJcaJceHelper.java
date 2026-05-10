// SPDX-License-Identifier: Apache-2.0
package org.hiero.consensus.crypto;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import javax.crypto.Cipher;
import javax.crypto.ExemptionMechanism;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import org.bouncycastle.jcajce.util.JcaJceHelper;

/**
 * A {@link JcaJceHelper} that routes ML-KEM lookups to a BC-pinned helper while sending all
 * other lookups to a "chain" helper (typically a {@code DefaultJcaJceHelper} that walks the
 * global JCA provider chain and lets ACCP intercept at position 1).
 * <p>
 * Why split routing this way: BCJSSE's {@code KemUtil} initializes ML-KEM with a BC-specific
 * {@code MLKEMParameterSpec}. If the {@code KeyPairGenerator.ML-KEM} comes from any non-BC
 * provider (SunJCE on JDK 25, ACCP, etc.), the parameter spec is rejected as
 * {@code InvalidAlgorithmParameterException}, BCJSSE silently disables the named group, and
 * the handshake falls back to a classical group with no warning. Pinning ML-KEM directly to
 * BC avoids that.
 * <p>
 * Modeled after {@code platform-sdk/consensus-tls-debug/.../MtlsDebugHybrid.HybridJcaJceHelper}
 * which is the verified-working configuration in the TLS-debug module.
 */
final class HybridJcaJceHelper implements JcaJceHelper {

    private final JcaJceHelper mlkem; // BC-pinned helper for ML-KEM algorithms
    private final JcaJceHelper chain; // helper for everything else (typically DefaultJcaJceHelper)

    HybridJcaJceHelper(@NonNull final JcaJceHelper mlkem, @NonNull final JcaJceHelper chain) {
        this.mlkem = mlkem;
        this.chain = chain;
    }

    private static boolean isMlKem(final String algorithm) {
        return algorithm != null && algorithm.startsWith("ML-KEM");
    }

    @Override
    public Cipher createCipher(final String algorithm)
            throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
        return (isMlKem(algorithm) ? mlkem : chain).createCipher(algorithm);
    }

    @Override
    public Mac createMac(final String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        return chain.createMac(algorithm);
    }

    @Override
    public KeyAgreement createKeyAgreement(final String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        return (isMlKem(algorithm) ? mlkem : chain).createKeyAgreement(algorithm);
    }

    @Override
    public AlgorithmParameterGenerator createAlgorithmParameterGenerator(final String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        return chain.createAlgorithmParameterGenerator(algorithm);
    }

    @Override
    public AlgorithmParameters createAlgorithmParameters(final String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        return chain.createAlgorithmParameters(algorithm);
    }

    @Override
    public KeyGenerator createKeyGenerator(final String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        return (isMlKem(algorithm) ? mlkem : chain).createKeyGenerator(algorithm);
    }

    @Override
    public KeyFactory createKeyFactory(final String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        return (isMlKem(algorithm) ? mlkem : chain).createKeyFactory(algorithm);
    }

    @Override
    public SecretKeyFactory createSecretKeyFactory(final String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        return chain.createSecretKeyFactory(algorithm);
    }

    @Override
    public KeyPairGenerator createKeyPairGenerator(final String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        return (isMlKem(algorithm) ? mlkem : chain).createKeyPairGenerator(algorithm);
    }

    @Override
    public MessageDigest createDigest(final String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        return chain.createDigest(algorithm);
    }

    @Override
    public MessageDigest createMessageDigest(final String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        return chain.createMessageDigest(algorithm);
    }

    @Override
    public Signature createSignature(final String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        return chain.createSignature(algorithm);
    }

    @Override
    public CertificateFactory createCertificateFactory(final String algorithm)
            throws NoSuchProviderException, CertificateException {
        return chain.createCertificateFactory(algorithm);
    }

    @Override
    public SecureRandom createSecureRandom(final String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        return chain.createSecureRandom(algorithm);
    }

    @Override
    public CertPathBuilder createCertPathBuilder(final String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        return chain.createCertPathBuilder(algorithm);
    }

    @Override
    public CertPathValidator createCertPathValidator(final String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        return chain.createCertPathValidator(algorithm);
    }

    @Override
    public CertStore createCertStore(final String type, final CertStoreParameters params)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        return chain.createCertStore(type, params);
    }

    @Override
    public ExemptionMechanism createExemptionMechanism(final String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        return chain.createExemptionMechanism(algorithm);
    }

    @Override
    public KeyStore createKeyStore(final String type) throws KeyStoreException, NoSuchProviderException {
        return chain.createKeyStore(type);
    }
}