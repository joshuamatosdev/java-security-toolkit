package io.github.joshuamatosdev.security.crypto.provider;

import io.github.joshuamatosdev.security.crypto.key.JcaKeyHandle;
import io.github.joshuamatosdev.security.crypto.key.KeyHandle;
import io.github.joshuamatosdev.security.crypto.registry.SignatureAlgorithm;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import org.jspecify.annotations.Nullable;

/**
 * A {@link SignatureProvider} implemented over the Java Cryptography Architecture. One class serves
 * every JCA-backed algorithm; the algorithm differs only by the construction parameters, so the
 * three providers this module ships ({@link SignatureProviders}) are configurations of the same
 * code rather than three near-duplicate classes.
 */
public final class JcaSignatureProvider implements SignatureProvider {

    private final SignatureAlgorithm algorithm;
    private final String keyPairGeneratorName;
    private final @Nullable AlgorithmParameterSpec keyGenSpec;
    private final String jcaSignatureName;
    private final String keyFactoryName;

    /**
     * @param algorithm the registry algorithm this provider reports
     * @param keyPairGeneratorName JCA {@link KeyPairGenerator} algorithm (e.g. {@code "Ed25519"},
     *     {@code "EC"})
     * @param keyGenSpec optional key-generation parameter spec (e.g. {@code secp256r1}); {@code null}
     *     when the generator needs none
     * @param jcaSignatureName JCA signature algorithm used to sign and verify (e.g. {@code
     *     "Ed25519"}, {@code "SHA256withECDSA"})
     * @param keyFactoryName JCA {@link KeyFactory} algorithm used to rebuild a public key from its
     *     encoded form on verify (e.g. {@code "Ed25519"}, {@code "EC"})
     */
    public JcaSignatureProvider(
            final SignatureAlgorithm algorithm,
            final String keyPairGeneratorName,
            final @Nullable AlgorithmParameterSpec keyGenSpec,
            final String jcaSignatureName,
            final String keyFactoryName) {
        this.algorithm = algorithm;
        this.keyPairGeneratorName = keyPairGeneratorName;
        this.keyGenSpec = keyGenSpec;
        this.jcaSignatureName = jcaSignatureName;
        this.keyFactoryName = keyFactoryName;
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
            // The JCA names are provider-internal, not caller-supplied; a missing algorithm here is a
            // genuine environment/config error and must surface, not read as a verification failure.
            key = KeyFactory.getInstance(keyFactoryName).generatePublic(new X509EncodedKeySpec(publicKey));
            verifier = java.security.Signature.getInstance(jcaSignatureName);
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("Verification unavailable for " + algorithm, e);
        } catch (final GeneralSecurityException e) {
            // The public key, payload, and signature are untrusted verification inputs. A key that
            // does not parse under this algorithm (e.g. a relabeled forgery) is a verification
            // failure, never a thrown error.
            return false;
        }
        try {
            verifier.initVerify(key);
            verifier.update(payload);
            return verifier.verify(signature);
        } catch (final GeneralSecurityException e) {
            // A wrong or malformed signature is a verification failure.
            return false;
        }
    }
}
