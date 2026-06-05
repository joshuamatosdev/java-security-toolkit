package io.github.joshuamatosdev.security.crypto.provider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Untrusted-input robustness of the verifier. ADR-0006 promises a verifier never crashes on
 * untrusted input: a malformed, relabeled, or absent key / payload / signature is a verification
 * failure ({@code false}); only a genuinely missing JCA algorithm throws. These cases probe inputs
 * the round-trip tests in {@code JcaSignatureProviderTest} never reach — {@code null} arrays and
 * structurally-invalid (non-SubjectPublicKeyInfo) key bytes — across every shipped provider,
 * including the EC factory whose decoder is the one most prone to unchecked parse failures.
 *
 * <p>Why this is important to test: algorithm migration depends on identical signing semantics
 * across providers and robust rejection of invalid key or signature material.
 */
class JcaSignatureProviderRobustnessTest {

    private static final byte[] PAYLOAD = "ledger entry 42".getBytes(StandardCharsets.UTF_8);
    private static final byte[] GARBAGE_KEY = {0x30, 0x05, 0x02, 0x03, 0x01, 0x02, 0x03};

    static Stream<Arguments> providers() {
        return Stream.of(
                Arguments.of("ed25519", SignatureProviders.ed25519()),
                Arguments.of("ecdsaP256", SignatureProviders.ecdsaP256()),
                Arguments.of("postQuantumPlaceholder", SignatureProviders.postQuantumPlaceholder()));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("providers")
    void verifyReturnsFalseForStructurallyInvalidPublicKey(
            final String name, final SignatureProvider provider) {
        assertThat(provider.verify(GARBAGE_KEY, PAYLOAD, new byte[64])).isFalse();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("providers")
    void verifyReturnsFalseForTruncatedPublicKey(
            final String name, final SignatureProvider provider) {
        final byte[] valid = provider.generateKey("k1").publicKey();
        final byte[] truncated = Arrays.copyOf(valid, valid.length / 2);

        assertThat(provider.verify(truncated, PAYLOAD, new byte[64])).isFalse();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("providers")
    void verifyDoesNotThrowOnNullArguments(final String name, final SignatureProvider provider) {
        final byte[] key = provider.generateKey("k1").publicKey();
        final byte[] signature = new byte[64];

        assertThatCode(() -> provider.verify(null, PAYLOAD, signature)).doesNotThrowAnyException();
        assertThatCode(() -> provider.verify(key, null, signature)).doesNotThrowAnyException();
        assertThatCode(() -> provider.verify(key, PAYLOAD, null)).doesNotThrowAnyException();
    }
}
