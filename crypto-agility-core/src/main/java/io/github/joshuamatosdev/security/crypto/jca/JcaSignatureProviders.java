package io.github.joshuamatosdev.security.crypto.jca;

import io.github.joshuamatosdev.security.crypto.api.SignatureAlgorithm;
import io.github.joshuamatosdev.security.crypto.api.SignatureProvider;
import java.security.spec.ECGenParameterSpec;

/** Factory methods for the local JCA providers shipped by the core library. */
public final class JcaSignatureProviders {

    private JcaSignatureProviders() {}

    /** EdDSA / Ed25519 over the JDK platform provider. */
    public static SignatureProvider ed25519() {
        return new JcaSignatureProvider(
                SignatureAlgorithm.ED25519, "Ed25519", null, "Ed25519", "Ed25519");
    }

    /** ECDSA over NIST P-256 with SHA-256 using JOSE-compatible P1363 signature bytes. */
    public static SignatureProvider ecdsaP256() {
        return new JcaSignatureProvider(
                SignatureAlgorithm.ECDSA_P256,
                "EC",
                new ECGenParameterSpec("secp256r1"),
                "SHA256withECDSAinP1363Format",
                "EC");
    }

    /**
     * ML-DSA-44 migration slot backed by an Ed25519 stand-in primitive.
     *
     * <p>This exercises the agility path but is not ML-DSA conformance or quantum resistance.
     */
    public static SignatureProvider postQuantumPlaceholder() {
        return new JcaSignatureProvider(
                SignatureAlgorithm.ML_DSA_44, "Ed25519", null, "Ed25519", "Ed25519");
    }
}
