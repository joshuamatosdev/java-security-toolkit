package io.github.joshuamatosdev.security.crypto.jca;

import io.github.joshuamatosdev.security.crypto.api.KeyHandle;
import io.github.joshuamatosdev.security.crypto.api.SignatureAlgorithm;
import io.github.joshuamatosdev.security.shared.RequiredText;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Objects;

final class JcaKeyHandle implements KeyHandle {

    private static final byte[] KEY_PAIR_VALIDATION_PAYLOAD =
            "JcaKeyHandle key-pair validation".getBytes(StandardCharsets.UTF_8);
    private final String keyId;
    private final SignatureAlgorithm algorithm;
    private final String jcaSignatureName;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    JcaKeyHandle(
            final String keyId,
            final JcaSignatureSpec spec,
            final KeyPair keyPair) {
        final KeyPair requiredKeyPair = Objects.requireNonNull(keyPair, "keyPair must not be null");
        this.keyId = requireNonBlank(keyId, "keyId");
        final JcaSignatureSpec requiredSpec = Objects.requireNonNull(spec, "spec must not be null");
        this.algorithm = requiredSpec.algorithm();
        this.jcaSignatureName = requiredSpec.signatureName();
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

    private static String requireNonBlank(final String value, final String field) {
        return RequiredText.require(value, field);
    }
}
