package io.github.joshuamatosdev.security.crypto.provider;

import io.github.joshuamatosdev.security.crypto.registry.SignatureAlgorithm;
import java.security.spec.ECGenParameterSpec;

/**
 * Factories for the signature providers this module ships. Each returns a {@link
 * JcaSignatureProvider} configured for one registry algorithm; together they are the hybrid set a
 * deployment wires into the registry — two classical algorithms and one post-quantum slot, all
 * behind the same {@link SignatureProvider} interface.
 */
public final class SignatureProviders {

    private SignatureProviders() {}

    /** EdDSA / Ed25519 over the JDK platform provider. */
    public static SignatureProvider ed25519() {
        return new JcaSignatureProvider(
                SignatureAlgorithm.ED25519, "Ed25519", null, "Ed25519", "Ed25519");
    }

    /** ECDSA over NIST P-256 with SHA-256. */
    public static SignatureProvider ecdsaP256() {
        return new JcaSignatureProvider(
                SignatureAlgorithm.ECDSA_P256,
                "EC",
                new ECGenParameterSpec("secp256r1"),
                "SHA256withECDSA",
                "EC");
    }

    /**
     * The post-quantum migration slot, reported as {@link SignatureAlgorithm#ML_DSA_44}.
     *
     * <p><b>PLACEHOLDER PRIMITIVE.</b> ML-DSA-44 (FIPS 204) is not in the JDK 21 platform, so this
     * provider exercises the registry / key-handle / call-site agility seam with an Ed25519 stand-in
     * primitive while reporting the {@code ML-DSA-44} wire identifier. It produces and verifies real
     * (Ed25519) signatures, so the end-to-end path is genuinely exercised — only the underlying
     * primitive is a stand-in.
     *
     * <p>The real implementation swaps the JCA names below for ML-DSA — JDK&nbsp;24's {@code
     * Signature.getInstance("ML-DSA")} or a BouncyCastle PQC provider — with no change to {@link
     * SignatureProvider}, the registry, or any call site. That substitutability is the property this
     * module demonstrates. See ADR-0006.
     */
    public static SignatureProvider postQuantumPlaceholder() {
        return new JcaSignatureProvider(
                SignatureAlgorithm.ML_DSA_44, "Ed25519", null, "Ed25519", "Ed25519");
    }
}
