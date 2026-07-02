package io.github.joshuamatosdev.security.crypto.testkit;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.crypto.api.KeyHandle;
import io.github.joshuamatosdev.security.crypto.api.SignatureProvider;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * Reusable contract tests for {@link SignatureProvider} implementations.
 *
 * <p>Provider implementers can create a JUnit class that implements this interface and returns
 * their provider from {@link #provider()}.
 */
public interface SignatureProviderContract {

    /** Provider under test. */
    SignatureProvider provider();

    /** Stable payload used by the default contract tests. */
    default byte[] contractPayload() {
        return "crypto provider contract payload".getBytes(StandardCharsets.UTF_8);
    }

    @Test
    default void validSignaturesVerify() {
        final SignatureProvider provider = provider();
        final KeyHandle key = provider.generateKey("contract-key-1");

        assertThat(provider.verify(key.publicKey(), contractPayload(), key.sign(contractPayload()))).isTrue();
    }

    @Test
    default void tamperedPayloadsFail() {
        final SignatureProvider provider = provider();
        final KeyHandle key = provider.generateKey("contract-key-1");
        final byte[] signature = key.sign(contractPayload());

        assertThat(provider.verify(
                        key.publicKey(),
                        "crypto provider contract tampered payload".getBytes(StandardCharsets.UTF_8),
                        signature))
                .isFalse();
    }

    @Test
    default void tamperedSignaturesFail() {
        final SignatureProvider provider = provider();
        final KeyHandle key = provider.generateKey("contract-key-1");
        final byte[] signature = key.sign(contractPayload());
        signature[signature.length - 1] ^= 0x01;

        assertThat(provider.verify(key.publicKey(), contractPayload(), signature)).isFalse();
    }

    @Test
    default void signaturesFromAnotherKeyFail() {
        final SignatureProvider provider = provider();
        final KeyHandle signingKey = provider.generateKey("contract-key-1");
        final KeyHandle otherKey = provider.generateKey("contract-key-2");

        assertThat(provider.verify(otherKey.publicKey(), contractPayload(), signingKey.sign(contractPayload())))
                .isFalse();
    }
}
