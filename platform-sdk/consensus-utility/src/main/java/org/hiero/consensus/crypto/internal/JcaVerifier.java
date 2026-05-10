// SPDX-License-Identifier: Apache-2.0
package org.hiero.consensus.crypto.internal;

import com.hedera.pbj.runtime.io.buffer.Bytes;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.hiero.base.crypto.BytesSignatureVerifier;
import org.hiero.base.crypto.CryptographyException;

/**
 * JCA-based implementation of {@link BytesSignatureVerifier}.
 */
public class JcaVerifier implements BytesSignatureVerifier {
    private static final Logger log = LogManager.getLogger(JcaVerifier.class);

    private final Signature verifier;

    /**
     * Constructor
     *
     * @param publicKey the public key
     * @param algorithm the signature algorithm
     * @param provider  the security provider
     */
    public JcaVerifier(
            @NonNull final PublicKey publicKey, @NonNull final String algorithm, @NonNull final String provider) {
        try {
            verifier = Signature.getInstance(algorithm, provider);
            log.info(
                    "[VERIFY/init] alg={} requestedProvider={} actualProvider={} pubKeyClass={} pubKeyAlg={}",
                    algorithm,
                    provider,
                    verifier.getProvider().getName(),
                    publicKey.getClass().getName(),
                    publicKey.getAlgorithm());
            verifier.initVerify(publicKey);
            log.info("[VERIFY/init.ok] alg={} provider={}", algorithm, verifier.getProvider().getName());
        } catch (final NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException e) {
            log.error(
                    "[VERIFY/init.FAILED] alg={} requestedProvider={} pubKeyClass={} pubKeyAlg={} cause={}",
                    algorithm,
                    provider,
                    publicKey.getClass().getName(),
                    publicKey.getAlgorithm(),
                    e.toString());
            throw new CryptographyException(e);
        }
    }

    @Override
    public boolean verify(@NonNull final Bytes data, @NonNull final Bytes signature) {
        try {
            data.updateSignature(verifier);
            return signature.verifySignature(verifier);
        } catch (final SignatureException e) {
            throw new CryptographyException(e);
        }
    }
}
