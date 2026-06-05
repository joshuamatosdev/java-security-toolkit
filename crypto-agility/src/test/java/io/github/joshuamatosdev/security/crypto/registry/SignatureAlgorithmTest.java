package io.github.joshuamatosdev.security.crypto.registry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/**
 * Signature Algorithm test coverage.
 *
 * <p>Why this is important to test: algorithm migration depends on identical signing semantics
 * across providers and robust rejection of invalid key or signature material.
 */
class SignatureAlgorithmTest {

    @Test
    void fromJoseAlgRoundTripsEveryRegisteredAlgorithm() {
        for (final SignatureAlgorithm algorithm : SignatureAlgorithm.values()) {
            assertThat(SignatureAlgorithm.fromJoseAlg(algorithm.joseAlg())).isEqualTo(algorithm);
        }
    }

    @Test
    void fromJoseAlgRejectsUnknownAlgorithm() {
        assertThatThrownBy(() -> SignatureAlgorithm.fromJoseAlg("RS256"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("RS256");
    }

    @Test
    void classicalAndPostQuantumFamiliesArePartitioned() {
        assertThat(SignatureAlgorithm.ED25519.family()).isEqualTo(AlgorithmFamily.CLASSICAL);
        assertThat(SignatureAlgorithm.ECDSA_P256.family()).isEqualTo(AlgorithmFamily.CLASSICAL);
        assertThat(SignatureAlgorithm.ML_DSA_44.family()).isEqualTo(AlgorithmFamily.POST_QUANTUM);
    }

    @Test
    void joseAlgValuesMatchTheWireRegistry() {
        assertThat(SignatureAlgorithm.ED25519.joseAlg()).isEqualTo("EdDSA");
        assertThat(SignatureAlgorithm.ECDSA_P256.joseAlg()).isEqualTo("ES256");
        assertThat(SignatureAlgorithm.ML_DSA_44.joseAlg()).isEqualTo("ML-DSA-44");
    }
}
