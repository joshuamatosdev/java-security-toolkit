package io.github.joshuamatosdev.security.crypto.api;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

class SignatureAlgorithmTest {

    @Test
    void fromJoseAlgRoundTripsBuiltInAlgorithms() {
        for (final SignatureAlgorithm algorithm :
                java.util.List.of(SignatureAlgorithm.ED25519, SignatureAlgorithm.ECDSA_P256)) {
            assertThat(SignatureAlgorithm.fromJoseAlg(algorithm.joseAlg())).isEqualTo(algorithm);
        }
    }

    @Test
    void customAlgorithmsAreFirstClassValues() {
        final SignatureAlgorithm custom = SignatureAlgorithm.of("CUSTOM-SIG-1");

        assertThat(custom.joseAlg()).isEqualTo("CUSTOM-SIG-1");
        assertThat(SignatureAlgorithm.fromJoseAlg("CUSTOM-SIG-1")).isEqualTo(custom);
    }
}
