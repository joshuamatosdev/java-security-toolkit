package io.github.joshuamatosdev.security.crypto.api;

/**
 * The cryptographic family a signature algorithm belongs to.
 *
 * <p>The family is policy/reporting metadata. Provider lookup and signing semantics dispatch on
 * {@link SignatureAlgorithm}, not on the family.
 */
public enum AlgorithmFamily {

    /** Pre-quantum public-key signatures such as Ed25519 and ECDSA P-256. */
    CLASSICAL,

    /** Lattice-based, quantum-resistant signatures such as ML-DSA. */
    POST_QUANTUM
}
