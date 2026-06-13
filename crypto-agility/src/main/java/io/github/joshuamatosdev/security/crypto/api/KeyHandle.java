package io.github.joshuamatosdev.security.crypto.api;

/**
 * A versioned reference to signing key material.
 *
 * <p>A handle exposes the public key and signing operation, never private key material. Production
 * implementations should bind this interface to KMS, HSM, hardware-backed wallet keys, or another
 * approved custody boundary.
 */
public interface KeyHandle {

    /** Versioned identifier for this key. */
    String keyId();

    /** Signature algorithm this handle signs with. */
    SignatureAlgorithm algorithm();

    /** Encoded public key, normally X.509 {@code SubjectPublicKeyInfo}. */
    byte[] publicKey();

    /** Signs the supplied payload with the bound private material. */
    byte[] sign(byte[] payload);
}
