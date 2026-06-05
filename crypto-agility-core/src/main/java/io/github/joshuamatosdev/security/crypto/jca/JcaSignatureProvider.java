package io.github.joshuamatosdev.security.crypto.jca;

import io.github.joshuamatosdev.security.crypto.api.KeyHandle;
import io.github.joshuamatosdev.security.crypto.api.SignatureAlgorithm;
import io.github.joshuamatosdev.security.crypto.api.SignatureProvider;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

/**
 * JCA-backed signature provider.
 *
 * <p>This is a concrete provider implementation, not the stable API surface. Applications that
 * need KMS/HSM custody should implement {@link SignatureProvider} directly.
 */
public final class JcaSignatureProvider implements SignatureProvider {

    private static final String EC_JCA_NAME = "EC";
    private static final String ED25519_JCA_NAME = "Ed25519";
    private static final String ECDSA_P256_SIGNATURE_NAME = "SHA256withECDSAinP1363Format";
    private static final String P256_CURVE_NAME = "secp256r1";

    private final SignatureAlgorithm algorithm;
    private final String keyPairGeneratorName;
    private final AlgorithmParameterSpec keyGenSpec;
    private final String jcaSignatureName;
    private final String keyFactoryName;
    private final ECParameterSpec expectedEcParameters;

    public JcaSignatureProvider(
            final SignatureAlgorithm algorithm,
            final String keyPairGeneratorName,
            final AlgorithmParameterSpec keyGenSpec,
            final String jcaSignatureName,
            final String keyFactoryName) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm must not be null");
        this.keyPairGeneratorName = requireNonBlank(keyPairGeneratorName, "keyPairGeneratorName");
        this.keyGenSpec = keyGenSpec;
        this.jcaSignatureName = requireNonBlank(jcaSignatureName, "jcaSignatureName");
        this.keyFactoryName = requireNonBlank(keyFactoryName, "keyFactoryName");
        this.expectedEcParameters = expectedEcParameters(keyGenSpec);
        requireProviderConfigurationForAlgorithm(
                this.algorithm,
                this.keyPairGeneratorName,
                this.keyGenSpec,
                this.jcaSignatureName,
                this.keyFactoryName,
                this.expectedEcParameters);
    }

    @Override
    public SignatureAlgorithm algorithm() {
        return algorithm;
    }

    @Override
    public KeyHandle generateKey(final String keyId) {
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance(keyPairGeneratorName);
            if (keyGenSpec != null) {
                generator.initialize(keyGenSpec);
            }
            final KeyPair keyPair = generator.generateKeyPair();
            return new JcaKeyHandle(keyId, algorithm, jcaSignatureName, keyPair);
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("Key generation failed for " + algorithm, e);
        }
    }

    @Override
    public boolean verify(final byte[] publicKey, final byte[] payload, final byte[] signature) {
        final PublicKey key;
        final java.security.Signature verifier;
        try {
            key = KeyFactory.getInstance(keyFactoryName).generatePublic(new X509EncodedKeySpec(publicKey));
            verifier = java.security.Signature.getInstance(jcaSignatureName);
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("Verification unavailable for " + algorithm, e);
        } catch (final GeneralSecurityException | RuntimeException e) {
            return false;
        }
        if (!hasExpectedKeyParameters(key)) {
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

    private static ECParameterSpec expectedEcParameters(final AlgorithmParameterSpec keyGenSpec) {
        if (keyGenSpec instanceof ECParameterSpec ecParameterSpec) {
            return ecParameterSpec;
        }
        if (!(keyGenSpec instanceof ECGenParameterSpec ecGenParameterSpec)) {
            return null;
        }
        try {
            final AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(ecGenParameterSpec);
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException(
                    "EC parameter resolution failed for " + ecGenParameterSpec.getName(), e);
        }
    }

    private static void requireProviderConfigurationForAlgorithm(
            final SignatureAlgorithm algorithm,
            final String keyPairGeneratorName,
            final AlgorithmParameterSpec keyGenSpec,
            final String jcaSignatureName,
            final String keyFactoryName,
            final ECParameterSpec expectedParameters) {
        if (algorithm == SignatureAlgorithm.ED25519
                && (!ED25519_JCA_NAME.equals(keyPairGeneratorName)
                || keyGenSpec != null
                || !ED25519_JCA_NAME.equals(jcaSignatureName)
                || !ED25519_JCA_NAME.equals(keyFactoryName))) {
            throw new IllegalArgumentException(
                    "ED25519 provider must use Ed25519 JCA primitives without key parameters");
        }
        if (algorithm == SignatureAlgorithm.ML_DSA_44
                && (!ED25519_JCA_NAME.equals(keyPairGeneratorName)
                || keyGenSpec != null
                || !ED25519_JCA_NAME.equals(jcaSignatureName)
                || !ED25519_JCA_NAME.equals(keyFactoryName))) {
            throw new IllegalArgumentException(
                    "ML_DSA_44 placeholder provider must use Ed25519 JCA primitives without key parameters");
        }
        if (algorithm == SignatureAlgorithm.ECDSA_P256) {
            if (!EC_JCA_NAME.equals(keyPairGeneratorName) || !EC_JCA_NAME.equals(keyFactoryName)) {
                throw new IllegalArgumentException("ECDSA_P256 provider must use EC JCA key primitives");
            }
            if (!ECDSA_P256_SIGNATURE_NAME.equals(jcaSignatureName)) {
                throw new IllegalArgumentException(
                        "ECDSA_P256 provider must use SHA256withECDSAinP1363Format");
            }
            if (!sameEcParameters(namedEcParameters(P256_CURVE_NAME), expectedParameters)) {
                throw new IllegalArgumentException("ECDSA_P256 provider must be constrained to secp256r1");
            }
        }
    }

    private static ECParameterSpec namedEcParameters(final String curveName) {
        try {
            final AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(curveName));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("EC parameter resolution failed for " + curveName, e);
        }
    }

    private boolean hasExpectedKeyParameters(final PublicKey key) {
        if (expectedEcParameters == null) {
            return true;
        }
        if (!(key instanceof ECPublicKey ecPublicKey)) {
            return false;
        }
        return sameEcParameters(expectedEcParameters, ecPublicKey.getParams());
    }

    private static boolean sameEcParameters(
            final ECParameterSpec expected, final ECParameterSpec actual) {
        return actual != null
                && expected.getCofactor() == actual.getCofactor()
                && expected.getOrder().equals(actual.getOrder())
                && expected.getGenerator().equals(actual.getGenerator())
                && expected.getCurve().equals(actual.getCurve());
    }

    private static String requireNonBlank(final String value, final String field) {
        Objects.requireNonNull(value, field + " must not be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        if (!value.equals(value.strip())) {
            throw new IllegalArgumentException(field + " must not contain leading or trailing whitespace");
        }
        if (value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(field + " must not contain control characters");
        }
        return value;
    }
}
