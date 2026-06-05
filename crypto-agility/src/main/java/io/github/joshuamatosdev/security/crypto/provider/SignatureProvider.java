package io.github.joshuamatosdev.security.crypto.provider;

import io.github.joshuamatosdev.security.crypto.key.KeyHandle;
import io.github.joshuamatosdev.security.crypto.registry.SignatureAlgorithm;

/**
 * The agility seam: all algorithm-specific logic lives behind this one interface, so a signature
 * algorithm can be added or swapped without changing any caller.
 *
 * <p>Refactored from the core platform's {@code JwsSignerPort}. A provider is bound to exactly one
 * {@link #algorithm()}; the {@code SignatureProviderRegistry} selects the provider for an algorithm,
 * and the call site never knows which one it received. Signing happens through the {@link KeyHandle}
 * (which binds the private material); the provider mints handles and verifies against a public key.
 *
 * <p>Why this exists: providers isolate algorithm-specific JCA details behind one signature seam.
 */
public interface SignatureProvider {

    /** The algorithm this provider implements. */
    SignatureAlgorithm algorithm();

    /**
     * Generates a fresh key and returns a versioned handle to it.
     *
     * @param keyId the version identifier to assign
     * @return a handle that signs with this provider's algorithm
     */
    KeyHandle generateKey(String keyId);

    /**
     * Verifies a signature against an encoded public key.
     *
     * @param publicKey the encoded public key (X.509 {@code SubjectPublicKeyInfo})
     * @param payload the original payload bytes
     * @param signature the signature bytes to check
     * @return {@code true} iff the signature is valid for the payload under the key
     */
    boolean verify(byte[] publicKey, byte[] payload, byte[] signature);
}
