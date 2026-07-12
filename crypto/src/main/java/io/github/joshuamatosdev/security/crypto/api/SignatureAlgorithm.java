package io.github.joshuamatosdev.security.crypto.api;

import io.github.joshuamatosdev.security.shared.RequiredText;

/**
 * Extensible wire identity for a signature algorithm.
 *
 * <p>The built-in constants cover the providers shipped by this library. Provider integrations may
 * create additional identities through {@link #of(String)} without editing this module, which keeps
 * the provider seam open for extension.
 *
 * @param joseAlg JOSE-style algorithm identifier carried in a signed document
 */
public record SignatureAlgorithm(String joseAlg) {

    /** EdDSA over Curve25519. */
    public static final SignatureAlgorithm ED25519 = new SignatureAlgorithm("EdDSA");

    /** ECDSA over NIST P-256 with SHA-256. */
    public static final SignatureAlgorithm ECDSA_P256 = new SignatureAlgorithm("ES256");

    public SignatureAlgorithm {
        joseAlg = RequiredText.require(joseAlg, "joseAlg");
    }

    /** The JOSE-style {@code alg} value emitted on the wire. */
    public static SignatureAlgorithm of(final String joseAlg) {
        if (ED25519.joseAlg.equals(joseAlg)) {
            return ED25519;
        }
        if (ECDSA_P256.joseAlg.equals(joseAlg)) {
            return ECDSA_P256;
        }
        return new SignatureAlgorithm(joseAlg);
    }

    /**
     * Creates an algorithm identity from its wire identifier.
     */
    public static SignatureAlgorithm fromJoseAlg(final String joseAlg) {
        return of(joseAlg);
    }

    /** String conversion hook used by configuration binding. */
    public static SignatureAlgorithm valueOf(final String joseAlg) {
        return of(joseAlg);
    }

    @Override
    public String toString() {
        return joseAlg;
    }
}
