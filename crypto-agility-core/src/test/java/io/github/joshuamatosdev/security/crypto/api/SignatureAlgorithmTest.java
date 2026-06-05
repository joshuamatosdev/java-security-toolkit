package io.github.joshuamatosdev.security.crypto.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

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
    void algorithmFamiliesArePartitioned() {
        assertThat(SignatureAlgorithm.ED25519.family()).isEqualTo(AlgorithmFamily.CLASSICAL);
        assertThat(SignatureAlgorithm.ECDSA_P256.family()).isEqualTo(AlgorithmFamily.CLASSICAL);
        assertThat(SignatureAlgorithm.ML_DSA_44.family()).isEqualTo(AlgorithmFamily.POST_QUANTUM);
    }
}
