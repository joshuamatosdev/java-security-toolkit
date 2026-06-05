package io.github.joshuamatosdev.security.crypto.key;

import io.github.joshuamatosdev.security.crypto.registry.SignatureAlgorithm;

/**
 * A versioned reference to a signing key that binds its private material internally and never
 * exposes it.
 *
 * <p>Refactored from the wallet's {@code HardwareKeyHandle}. Call sites hold a handle, ask it to
 * {@link #sign(byte[])}, and read its {@link #publicKey()} for verification — they never see, copy,
 * or pass the private key. The {@link #keyId()} is the version: rotating a key means issuing a new
 * handle under a new id, while old material referenced by old handles still verifies.
 *
 * <p>The {@link #algorithm()} is part of the handle's identity, so a call site that asks the handle
 * which algorithm it is gets an answer without naming any algorithm itself — the basis of the
 * agility property.
 *
 * <p>Why this exists: key handles hide private material while letting signing call sites stay
 * algorithm-agnostic.
 */
public interface KeyHandle {

    /** The versioned identifier of this key. */
    String keyId();

    /** The signature algorithm this handle signs with. */
    SignatureAlgorithm algorithm();

    /** The encoded public key (X.509 {@code SubjectPublicKeyInfo}), for verification. */
    byte[] publicKey();

    /**
     * Signs the payload with the bound private material.
     *
     * @param payload the bytes to sign
     * @return the signature bytes
     */
    byte[] sign(byte[] payload);
}
