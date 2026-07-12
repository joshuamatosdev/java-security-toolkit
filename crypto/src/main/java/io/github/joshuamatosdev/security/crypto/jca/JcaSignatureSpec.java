package io.github.joshuamatosdev.security.crypto.jca;

import io.github.joshuamatosdev.security.crypto.api.SignatureAlgorithm;
import io.github.joshuamatosdev.security.shared.RequiredText;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;
import java.util.function.Predicate;
import org.jspecify.annotations.Nullable;

/**
 * Data-shaped JCA configuration for one signature algorithm.
 *
 * <p>Supplying a new spec creates a new provider without modifying the registry, signer, key
 * handle, or generic JCA implementation.
 */
public record JcaSignatureSpec(
        SignatureAlgorithm algorithm,
        String keyPairGeneratorName,
        @Nullable AlgorithmParameterSpec keyGenerationParameters,
        String signatureName,
        String keyFactoryName,
        Predicate<KeyPair> generatedKeyValidator,
        Predicate<PublicKey> verificationKeyValidator) {

    public JcaSignatureSpec {
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        keyPairGeneratorName = RequiredText.require(keyPairGeneratorName, "keyPairGeneratorName");
        signatureName = RequiredText.require(signatureName, "signatureName");
        keyFactoryName = RequiredText.require(keyFactoryName, "keyFactoryName");
        Objects.requireNonNull(generatedKeyValidator, "generatedKeyValidator must not be null");
        Objects.requireNonNull(verificationKeyValidator, "verificationKeyValidator must not be null");
    }

    void requireValidGeneratedKey(final KeyPair keyPair) {
        if (!generatedKeyValidator.test(Objects.requireNonNull(keyPair, "keyPair must not be null"))) {
            throw new IllegalStateException("Generated key material does not satisfy " + algorithm);
        }
    }

    boolean acceptsVerificationKey(final PublicKey publicKey) {
        return verificationKeyValidator.test(publicKey);
    }
}
