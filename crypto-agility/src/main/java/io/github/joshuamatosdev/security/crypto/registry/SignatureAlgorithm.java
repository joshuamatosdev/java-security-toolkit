package io.github.joshuamatosdev.security.crypto.registry;

import java.util.Arrays;

/**
 * The algorithm registry: the single authority that names every signature algorithm this module
 * supports and carries its wire identifier and policy metadata.
 *
 * <p>Refactored from the wallet's {@code KeyAlgorithm} enum. Call sites never write algorithm
 * strings inline — they reference an entry here, and the wire {@code alg} value comes from
 * {@link #joseAlg()}. Adding an algorithm is a single new entry plus a provider; no call site that
 * signs or verifies changes (the agility property).
 *
 * <p>The {@code alg} values follow the JOSE {@code alg} header registry ({@code EdDSA}, {@code
 * ES256}) and the post-quantum {@code ML-DSA-44} identifier.
 *
 * <p>Why this exists: registry types make algorithm identity and provider lookup explicit so
 * migrations change configuration rather than callers.
 */
public enum SignatureAlgorithm {

    /** EdDSA over Curve25519. Classical, FIPS 186-5 approved. */
    ED25519("EdDSA", AlgorithmFamily.CLASSICAL, true),

    /** ECDSA over NIST P-256 with SHA-256. Classical, FIPS 186-4 approved. */
    ECDSA_P256("ES256", AlgorithmFamily.CLASSICAL, true),

    /** ML-DSA-44 (FIPS 204). Post-quantum; the migration target this module reserves a slot for. */
    ML_DSA_44("ML-DSA-44", AlgorithmFamily.POST_QUANTUM, true);

    private final String joseAlg;
    private final AlgorithmFamily family;
    private final boolean fipsApproved;

    SignatureAlgorithm(final String joseAlg, final AlgorithmFamily family, final boolean fipsApproved) {
        this.joseAlg = joseAlg;
        this.family = family;
        this.fipsApproved = fipsApproved;
    }

    /** The JOSE {@code alg} header value this algorithm emits on the wire. */
    public String joseAlg() {
        return joseAlg;
    }

    /** Classical or post-quantum. */
    public AlgorithmFamily family() {
        return family;
    }

    /**
     * Whether this algorithm <em>identity</em> is FIPS-approved — standardized as an approved
     * security function (ML-DSA-44 by FIPS&nbsp;204, EdDSA by FIPS&nbsp;186-5, ECDSA P-256 by
     * FIPS&nbsp;186-4).
     *
     * <p><b>An approved algorithm is not a validated implementation.</b> This flag describes the
     * algorithm, not the provider wired in for it. Under the NIST Cryptographic Module Validation
     * Program, a deployment "does not meet the FIPS 140-2 or FIPS 140-3 requirements by simply
     * implementing an approved security function" — module validation is earned by an implementation,
     * never conferred by the algorithm. So a runtime gate must not read {@code fipsApproved() &&
     * family() == POST_QUANTUM} as "real post-quantum protection is active": the post-quantum slot
     * ships an Ed25519 stand-in (see {@code SignatureProviders.postQuantumPlaceholder}) that is
     * FIPS-approved by identity yet is not a validated ML-DSA implementation. Such a gate must also
     * confirm the wired provider is the real algorithm.
     *
     * @see <a
     *     href="https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules">NIST
     *     CMVP — an approved security function is not a validated module</a>
     */
    public boolean fipsApproved() {
        return fipsApproved;
    }

    /**
     * Resolves the registry entry for a wire {@code alg} value.
     *
     * @param joseAlg the JOSE {@code alg} header value (e.g. {@code "EdDSA"})
     * @return the matching algorithm
     * @throws IllegalArgumentException if no registered algorithm carries that {@code alg} value
     */
    public static SignatureAlgorithm fromJoseAlg(final String joseAlg) {
        return Arrays.stream(values())
                .filter(algorithm -> algorithm.joseAlg.equals(joseAlg))
                .findFirst()
                .orElseThrow(
                        () -> new IllegalArgumentException("Unsupported signature algorithm: " + joseAlg));
    }
}
