// SPDX-License-Identifier: Apache-2.0
package org.hiero.sloth.fixtures.internal;

import static com.swirlds.logging.legacy.LogMarker.DEMO_INFO;
import static com.swirlds.logging.legacy.LogMarker.EXCEPTION;
import static java.util.Objects.requireNonNull;
import static org.hiero.consensus.crypto.CryptoConstants.getBCProviderName;
import static org.hiero.consensus.crypto.SigningImplementation.ED25519_ACCP;
import static org.hiero.consensus.crypto.SigningImplementation.RSA_ACCP;

import com.google.protobuf.ByteString;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.hiero.consensus.model.node.KeysAndCerts;
import org.hiero.sloth.fixtures.container.proto.ProtoKeysAndCerts;

/**
 * Utility class for converting between {@link KeysAndCerts} and {@link ProtoKeysAndCerts}.
 * Provides methods to serialize and deserialize cryptographic keys and certificates
 * for use in protocol buffers.
 */
public class KeysAndCertsConverter {
    private static final Logger log = LogManager.getLogger();
    static {
        getBCProviderName();
    }

    private KeysAndCertsConverter() {}

    /**
     * Converts a {@link KeysAndCerts} instance to a {@link ProtoKeysAndCerts} protocol buffer.
     *
     * @param keysAndCerts the {@link KeysAndCerts} instance to convert; must not be null
     * @return the corresponding {@link ProtoKeysAndCerts} protocol buffer
     * @throws RuntimeException if a certificate encoding error occurs
     */
    public static ProtoKeysAndCerts toProto(@NonNull final KeysAndCerts keysAndCerts) {
        requireNonNull(keysAndCerts, "keysAndCerts must not be null");
        try {
            return ProtoKeysAndCerts.newBuilder()
                    .setSigKeyType(keysAndCerts.sigKeyPair().getPrivate().getAlgorithm())
                    .setSigPrivateKey(ByteString.copyFrom(
                            keysAndCerts.sigKeyPair().getPrivate().getEncoded()))
                    .setSigPublicKey(ByteString.copyFrom(
                            keysAndCerts.sigKeyPair().getPublic().getEncoded()))
                    .setAgrKeyType(keysAndCerts.agrKeyPair().getPrivate().getAlgorithm())
                    .setAgrPrivateKey(ByteString.copyFrom(
                            keysAndCerts.agrKeyPair().getPrivate().getEncoded()))
                    .setAgrPublicKey(ByteString.copyFrom(
                            keysAndCerts.agrKeyPair().getPublic().getEncoded()))
                    .setSigCertType(keysAndCerts.sigCert().getType())
                    .setSigCertificate(
                            ByteString.copyFrom(keysAndCerts.sigCert().getEncoded()))
                    .setAgrCertType(keysAndCerts.agrCert().getType())
                    .setAgrCertificate(
                            ByteString.copyFrom(keysAndCerts.agrCert().getEncoded()))
                    .build();
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Converts a {@link ProtoKeysAndCerts} protocol buffer to a {@link KeysAndCerts} instance.
     *
     * @param proto the {@link ProtoKeysAndCerts} protocol buffer to convert; must not be null
     * @return the corresponding {@link KeysAndCerts} instance
     * @throws RuntimeException if a certificate or key decoding error occurs
     */
    public static KeysAndCerts fromProto(@NonNull final ProtoKeysAndCerts proto) {
        requireNonNull(proto, "proto cannot be null");
        try {

            var sigKeyType= proto.getSigKeyType();
            if(sigKeyType.equalsIgnoreCase("EdDSA")){
                sigKeyType= "Ed25519";
            }
            final KeyFactory sigKeyFactory = KeyFactory.getInstance(sigKeyType);
            log.info(DEMO_INFO.getMarker(),
                    "[KEYLOAD/sig.factory] KeyFactory.provider={}",
                    sigKeyFactory.getProvider().getName());
            final PrivateKey sigPriv = sigKeyFactory.generatePrivate(
                    new PKCS8EncodedKeySpec(proto.getSigPrivateKey().toByteArray()));
            final PublicKey sigPub = sigKeyFactory.generatePublic(
                    new X509EncodedKeySpec(proto.getSigPublicKey().toByteArray()));
            log.info(DEMO_INFO.getMarker(),
                    "[KEYLOAD/sig.done] pubClass={} privClass={} pubAlg={}",
                    sigPub.getClass().getName(),
                    sigPriv.getClass().getName(),
                    sigPub.getAlgorithm());
            final KeyPair sigPair = new KeyPair(sigPub, sigPriv);

            // Pin agr KeyFactory to BC. The agrKey was generated by BC (per CryptoConstants);
            // PKCS#8 encoding details for ML-DSA may differ subtly between BC and SunJCE.
            final KeyFactory agrKeyFactory;
            agrKeyFactory = KeyFactory.getInstance(proto.getAgrKeyType());
            log.info(DEMO_INFO.getMarker(),
                    "[KEYLOAD/agr.factory] agrKeyType={} KeyFactory.provider={}",
                    proto.getAgrKeyType(),
                    agrKeyFactory.getProvider().getName());
            final PrivateKey agrPriv = agrKeyFactory.generatePrivate(
                    new PKCS8EncodedKeySpec(proto.getAgrPrivateKey().toByteArray()));
            final PublicKey agrPub = agrKeyFactory.generatePublic(
                    new X509EncodedKeySpec(proto.getAgrPublicKey().toByteArray()));
            log.info(
                    DEMO_INFO.getMarker(),
                    "[KEYLOAD/agr.done] pubClass={} privClass={} pubAlg={}",
                    agrPub.getClass().getName(),
                    agrPriv.getClass().getName(),
                    agrPub.getAlgorithm());
            final KeyPair agrPair = new KeyPair(agrPub, agrPriv);

            // Pin CertificateFactory to BC. Without a provider, the JDK default X.509 factory
            // parses ML-DSA SubjectPublicKeyInfo as sun.security.x509.NamedX509Key — and BCJSSE
            // then can't pair that public key with the BC-class private key in the keystore,
            // so the credential is silently rejected ("no selectable cipher suite" at handshake).
            var sigcertFactory =
                    "RSA".equalsIgnoreCase(proto.getSigKeyType()) || proto.getSigKeyType().contains("ML-DSA")
                            ? CertificateFactory.getInstance(proto.getAgrCertType(), "BC")
                            : CertificateFactory.getInstance(proto.getSigCertType());

            var agrCertFactory =
                    "RSA".equalsIgnoreCase(proto.getAgrKeyType()) || proto.getAgrKeyType().contains("ML-DSA")
                            ? CertificateFactory.getInstance(proto.getAgrCertType(), "BC")
                            : CertificateFactory.getInstance(proto.getSigCertType());

            final X509Certificate sigCert = (X509Certificate) sigcertFactory.generateCertificate(
                    new ByteArrayInputStream(proto.getSigCertificate().toByteArray()));

            final X509Certificate agrCert = (X509Certificate) agrCertFactory.generateCertificate(
                    new ByteArrayInputStream(proto.getAgrCertificate().toByteArray()));
            log.info(DEMO_INFO.getMarker(),
                    "[KEYLOAD/sig.cert] sigCertFactory.provider={} cert.pubClass={}",
                    sigcertFactory.getProvider().getName(),
                    sigCert.getPublicKey().getClass().getName());
            log.info(DEMO_INFO.getMarker(),
                    "[KEYLOAD/sig.cert] agrCertFactory.provider={} cert.pubClass={}",
                    agrCertFactory.getProvider().getName(),
                    sigCert.getPublicKey().getClass().getName());
            return new KeysAndCerts(sigPair, agrPair, sigCert, agrCert);
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            // Log before rethrowing — the gRPC framework swallows this cause and only sends
            // "UNKNOWN: Application error processing RPC" to the orchestrator, leaving us blind.
            log.error(EXCEPTION.getMarker(),
                    "[KeysAndCertsConverter.fromProto] FAILED: sigKeyType={}, agrKeyType={}, sigCertType={}, agrCertType={}, cause: {}",
                    proto.getSigKeyType(), proto.getAgrKeyType(), proto.getSigCertType(), proto.getAgrCertType(), e);
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }
}
