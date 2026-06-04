package io.github.joshuamatosdev.security.crypto.key;

import io.github.joshuamatosdev.security.crypto.registry.SignatureAlgorithm;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * A {@link KeyHandle} backed by a JCA {@link KeyPair}. One implementation serves every JCA-backed
 * algorithm — the algorithm differs only by the registry entry and the JCA signature name passed in.
 *
 * <p>The {@link PrivateKey} is held in a private field and is never returned by any accessor; the
 * only thing a caller can do with the private side is invoke {@link #sign(byte[])}. This mirrors the
 * wallet's hardware-bound handle contract with a software keystore: the material is encapsulated,
 * not passed around.
 */
public final class JcaKeyHandle implements KeyHandle {

    private final String keyId;
    private final SignatureAlgorithm algorithm;
    private final String jcaSignatureName;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    /**
     * @param keyId the versioned key identifier
     * @param algorithm the registry algorithm this handle reports
     * @param jcaSignatureName the JCA {@link Signature} algorithm name to sign with (e.g. {@code
     *     "Ed25519"}, {@code "SHA256withECDSA"})
     * @param keyPair the underlying JCA key pair
     */
    public JcaKeyHandle(
            final String keyId,
            final SignatureAlgorithm algorithm,
            final String jcaSignatureName,
            final KeyPair keyPair) {
        this.keyId = keyId;
        this.algorithm = algorithm;
        this.jcaSignatureName = jcaSignatureName;
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
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
}
