package io.github.joshuamatosdev.security.crypto.provider;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.crypto.key.KeyHandle;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class JcaSignatureProviderTest {

    private static final byte[] PAYLOAD = "ledger entry 42".getBytes(StandardCharsets.UTF_8);

    static Stream<Arguments> providers() {
        return Stream.of(
                Arguments.of(SignatureProviders.ed25519()),
                Arguments.of(SignatureProviders.ecdsaP256()),
                Arguments.of(SignatureProviders.postQuantumPlaceholder()));
    }

    @ParameterizedTest
    @MethodSource("providers")
    void generatedHandleReportsProviderAlgorithmAndKeyId(final SignatureProvider provider) {
        final KeyHandle handle = provider.generateKey("k1");

        assertThat(handle.keyId()).isEqualTo("k1");
        assertThat(handle.algorithm()).isEqualTo(provider.algorithm());
        assertThat(handle.publicKey()).isNotEmpty();
    }

    @ParameterizedTest
    @MethodSource("providers")
    void signThenVerifyRoundTrips(final SignatureProvider provider) {
        final KeyHandle handle = provider.generateKey("k1");

        final byte[] signature = handle.sign(PAYLOAD);

        assertThat(provider.verify(handle.publicKey(), PAYLOAD, signature)).isTrue();
    }

    @ParameterizedTest
    @MethodSource("providers")
    void verifyRejectsTamperedPayload(final SignatureProvider provider) {
        final KeyHandle handle = provider.generateKey("k1");
        final byte[] signature = handle.sign(PAYLOAD);

        final byte[] tampered = "ledger entry 43".getBytes(StandardCharsets.UTF_8);

        assertThat(provider.verify(handle.publicKey(), tampered, signature)).isFalse();
    }

    @ParameterizedTest
    @MethodSource("providers")
    void verifyRejectsTamperedSignature(final SignatureProvider provider) {
        final KeyHandle handle = provider.generateKey("k1");
        final byte[] signature = handle.sign(PAYLOAD);
        signature[signature.length - 1] ^= 0x01;

        assertThat(provider.verify(handle.publicKey(), PAYLOAD, signature)).isFalse();
    }

    @ParameterizedTest
    @MethodSource("providers")
    void verifyRejectsSignatureFromAnotherKey(final SignatureProvider provider) {
        final KeyHandle signingKey = provider.generateKey("k1");
        final KeyHandle otherKey = provider.generateKey("k2");
        final byte[] signature = signingKey.sign(PAYLOAD);

        assertThat(provider.verify(otherKey.publicKey(), PAYLOAD, signature)).isFalse();
    }
}
