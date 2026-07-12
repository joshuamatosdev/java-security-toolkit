package io.github.joshuamatosdev.security.crypto.jca;

import io.github.joshuamatosdev.security.crypto.api.KeyHandle;
import io.github.joshuamatosdev.security.crypto.api.SignatureAlgorithm;
import io.github.joshuamatosdev.security.crypto.api.SignatureProvider;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

/**
 * JCA-backed signature provider.
 *
 * <p>This is a concrete provider implementation, not the stable API surface. Applications that
 * need KMS/HSM custody should implement {@link SignatureProvider} directly.
 */
public final class JcaSignatureProvider implements SignatureProvider {

    private final JcaSignatureSpec spec;

    public JcaSignatureProvider(final JcaSignatureSpec spec) {
        this.spec = Objects.requireNonNull(spec, "spec must not be null");
    }

    @Override
    public SignatureAlgorithm algorithm() {
        return spec.algorithm();
    }

    @Override
    public KeyHandle generateKey(final String keyId) {
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance(spec.keyPairGeneratorName());
            if (spec.keyGenerationParameters() != null) {
                generator.initialize(spec.keyGenerationParameters());
            }
            final KeyPair keyPair = generator.generateKeyPair();
            spec.requireValidGeneratedKey(keyPair);
            return new JcaKeyHandle(keyId, spec, keyPair);
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("Key generation failed for " + spec.algorithm(), e);
        }
    }

    @Override
    public boolean verify(final byte[] publicKey, final byte[] payload, final byte[] signature) {
        final PublicKey key;
        final java.security.Signature verifier;
        try {
            key = KeyFactory.getInstance(spec.keyFactoryName()).generatePublic(new X509EncodedKeySpec(publicKey));
            verifier = java.security.Signature.getInstance(spec.signatureName());
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("Verification unavailable for " + spec.algorithm(), e);
        } catch (final GeneralSecurityException | RuntimeException e) {
            return false;
        }
        if (!spec.acceptsVerificationKey(key)) {
            return false;
        }
        try {
            verifier.initVerify(key);
            verifier.update(payload);
            return verifier.verify(signature);
        } catch (final GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

}
