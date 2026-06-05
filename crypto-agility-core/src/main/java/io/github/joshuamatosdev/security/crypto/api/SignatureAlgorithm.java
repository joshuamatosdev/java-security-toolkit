package io.github.joshuamatosdev.security.crypto.api;

import java.util.Arrays;

/**
 * Stable algorithm identities supported by the crypto-agility API.
 *
 * <p>The {@code alg} values are wire identifiers. They are intentionally centralized here so
 * callers do not spread algorithm string literals across signing and verification code.
 */
public enum SignatureAlgorithm {

    /** EdDSA over Curve25519. Classical, FIPS 186-5 approved as an algorithm identity. */
    ED25519("EdDSA", AlgorithmFamily.CLASSICAL, true),

    /** ECDSA over NIST P-256 with SHA-256. Classical, FIPS 186-4 approved. */
    ECDSA_P256("ES256", AlgorithmFamily.CLASSICAL, true),

    /** ML-DSA-44 (FIPS 204). Post-quantum migration target. */
    ML_DSA_44("ML-DSA-44", AlgorithmFamily.POST_QUANTUM, true);

    private final String joseAlg;
    private final AlgorithmFamily family;
    private final boolean fipsApproved;

    SignatureAlgorithm(final String joseAlg, final AlgorithmFamily family, final boolean fipsApproved) {
        this.joseAlg = joseAlg;
        this.family = family;
        this.fipsApproved = fipsApproved;
    }

    /** The JOSE-style {@code alg} value emitted on the wire. */
    public String joseAlg() {
        return joseAlg;
    }

    /** Classical or post-quantum family metadata. */
    public AlgorithmFamily family() {
        return family;
    }

    /**
     * Whether this algorithm identity is FIPS-approved.
     *
     * <p>This is not runtime provider validation. A deployment that needs FIPS 140-2/140-3 posture
     * must validate the concrete cryptographic module and provider configuration separately.
     */
    public boolean fipsApproved() {
        return fipsApproved;
    }

    /**
     * Resolves a registered algorithm from its wire identifier.
     *
     * @throws IllegalArgumentException when the value is unknown
     */
    public static SignatureAlgorithm fromJoseAlg(final String joseAlg) {
        return Arrays.stream(values())
                .filter(algorithm -> algorithm.joseAlg.equals(joseAlg))
                .findFirst()
                .orElseThrow(
                        () -> new IllegalArgumentException("Unsupported signature algorithm: " + joseAlg));
    }
}
