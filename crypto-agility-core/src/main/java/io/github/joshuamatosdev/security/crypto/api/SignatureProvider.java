package io.github.joshuamatosdev.security.crypto.api;

/**
 * Provider seam for algorithm-specific signing and verification behavior.
 *
 * <p>A provider is bound to exactly one {@link SignatureAlgorithm}. Implementations own key
 * generation/resolution and verification details for that algorithm, while application call sites
 * depend only on this interface.
 */
public interface SignatureProvider {

    /** Algorithm implemented by this provider. */
    SignatureAlgorithm algorithm();

    /** Generates or provisions a new key handle under the supplied versioned id. */
    KeyHandle generateKey(String keyId);

    /** Returns {@code true} only when the signature is valid for the payload and encoded key. */
    boolean verify(byte[] publicKey, byte[] payload, byte[] signature);
}
