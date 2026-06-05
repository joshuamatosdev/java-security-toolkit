package io.github.joshuamatosdev.security.crypto.api;

/**
 * Chooses the current signing key id for an algorithm.
 *
 * <p>Rotation policy belongs behind this seam. A simple deployment can return one configured id;
 * production deployments can consult a rotation schedule or key-control plane.
 */
@FunctionalInterface
public interface KeyIdStrategy {

    /** Returns the active signing key id for the supplied algorithm. */
    String currentKeyId(SignatureAlgorithm algorithm);
}
