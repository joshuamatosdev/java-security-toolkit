package io.github.joshuamatosdev.security.crypto.api;

/**
 * Resolves a signing key handle for an algorithm and versioned key id.
 *
 * <p>Applications normally implement this with KMS/HSM lookup, a keystore, wallet custody, or a
 * tenant-aware key-control plane.
 */
@FunctionalInterface
public interface KeyHandleResolver {

    /** Resolves the key handle to use for signing. */
    KeyHandle resolve(SignatureAlgorithm algorithm, String keyId);
}
