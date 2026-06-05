package io.github.joshuamatosdev.security.crypto.registry;

/**
 * The cryptographic family a signature algorithm belongs to.
 *
 * <p>The distinction matters for the migration story this module demonstrates: a deployment runs
 * {@link #CLASSICAL} today and adds a {@link #POST_QUANTUM} algorithm alongside it without changing
 * any signing or verifying call site. The family is metadata for policy and reporting — the agility
 * seam itself dispatches on the algorithm, not the family.
 *
 * <p>Why this exists: registry types make algorithm identity and provider lookup explicit so
 * migrations change configuration rather than callers.
 */
public enum AlgorithmFamily {

    /** Pre-quantum public-key signatures (Ed25519, ECDSA P-256). */
    CLASSICAL,

    /** Lattice-based, quantum-resistant signatures (ML-DSA). */
    POST_QUANTUM
}
