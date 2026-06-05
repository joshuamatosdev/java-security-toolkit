package io.github.joshuamatosdev.security.crypto.key;

import io.github.joshuamatosdev.security.crypto.registry.SignatureAlgorithm;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Objects;

/**
 * A {@link KeyHandle} backed by a JCA {@link KeyPair}. One implementation serves every JCA-backed
 * algorithm — the algorithm differs only by the registry entry and the JCA signature name passed in.
 *
 * <p>The {@link PrivateKey} is held in a private field and is never returned by any accessor; the
 * only thing a caller can do with the private side is invoke {@link #sign(byte[])}. This mirrors the
 * wallet's hardware-bound handle contract with a software keystore: the material is encapsulated,
 * not passed around.
 *
 * <p>Why this exists: key handles hide private material while letting signing call sites stay
 * algorithm-agnostic.
 */
public final class JcaKeyHandle implements KeyHandle {

    private static final byte[] KEY_PAIR_VALIDATION_PAYLOAD =
            "JcaKeyHandle key-pair validation".getBytes(StandardCharsets.UTF_8);
    private static final String ED25519_JCA_NAME = "Ed25519";
    private static final String ECDSA_P256_SIGNATURE_NAME = "SHA256withECDSAinP1363Format";

    private final String keyId;
    private final SignatureAlgorithm algorithm;
    private final String jcaSignatureName;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    /**
     * @param keyId the versioned key identifier
     * @param algorithm the registry algorithm this handle reports
     * @param jcaSignatureName the JCA {@link Signature} algorithm name to sign with (e.g. {@code
     *     "Ed25519"}, {@code "SHA256withECDSAinP1363Format"})
     * @param keyPair the underlying JCA key pair
     */
    public JcaKeyHandle(
            final String keyId,
            final SignatureAlgorithm algorithm,
            final String jcaSignatureName,
            final KeyPair keyPair) {
        final KeyPair requiredKeyPair = Objects.requireNonNull(keyPair, "keyPair must not be null");
        this.keyId = requireNonBlank(keyId, "keyId");
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm must not be null");
        this.jcaSignatureName = requireNonBlank(jcaSignatureName, "jcaSignatureName");
        requireSignatureNameForAlgorithm(this.algorithm, this.jcaSignatureName);
        this.privateKey =
                Objects.requireNonNull(requiredKeyPair.getPrivate(), "privateKey must not be null");
        this.publicKey =
                Objects.requireNonNull(requiredKeyPair.getPublic(), "publicKey must not be null");
        requireMatchingKeyPair(this.jcaSignatureName, this.privateKey, this.publicKey);
    }

    @Override
    public String keyId() {
        return keyId;
    }

    @Override
    public SignatureAlgorithm algorithm() {
        return algorithm;
    }

    @Override
    public byte[] publicKey() {
        return publicKey.getEncoded();
    }

    @Override
    public byte[] sign(final byte[] payload) {
        try {
            final Signature signature = Signature.getInstance(jcaSignatureName);
            signature.initSign(privateKey);
            signature.update(payload);
            return signature.sign();
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("Signing failed for key " + keyId, e);
        }
    }

    private static void requireMatchingKeyPair(
            final String jcaSignatureName, final PrivateKey privateKey, final PublicKey publicKey) {
        try {
            final Signature signer = Signature.getInstance(jcaSignatureName);
            signer.initSign(privateKey);
            signer.update(KEY_PAIR_VALIDATION_PAYLOAD);
            final byte[] proof = signer.sign();

            final Signature verifier = Signature.getInstance(jcaSignatureName);
            verifier.initVerify(publicKey);
            verifier.update(KEY_PAIR_VALIDATION_PAYLOAD);
            if (!verifier.verify(proof)) {
                throw new IllegalArgumentException(
                        "keyPair public key must verify signatures from its private key");
            }
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("Signing unavailable for algorithm " + jcaSignatureName, e);
        } catch (final GeneralSecurityException e) {
            throw new IllegalArgumentException(
                    "keyPair public key must verify signatures from its private key", e);
        }
    }

    private static void requireSignatureNameForAlgorithm(
            final SignatureAlgorithm algorithm, final String jcaSignatureName) {
        if (algorithm == SignatureAlgorithm.ED25519 && !ED25519_JCA_NAME.equals(jcaSignatureName)) {
            throw new IllegalArgumentException("ED25519 key handle must use Ed25519");
        }
        if (algorithm == SignatureAlgorithm.ML_DSA_44 && !ED25519_JCA_NAME.equals(jcaSignatureName)) {
            throw new IllegalArgumentException("ML_DSA_44 placeholder key handle must use Ed25519");
        }
        if (algorithm == SignatureAlgorithm.ECDSA_P256
                && !ECDSA_P256_SIGNATURE_NAME.equals(jcaSignatureName)) {
            throw new IllegalArgumentException(
                    "ECDSA_P256 key handle must use SHA256withECDSAinP1363Format");
        }
    }

    private static String requireNonBlank(final String value, final String field) {
        Objects.requireNonNull(value, field + " must not be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        if (!value.equals(value.strip())) {
            throw new IllegalArgumentException(
                    field + " must not contain leading or trailing whitespace");
        }
        if (value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(field + " must not contain control characters");
        }
        return value;
    }
}
