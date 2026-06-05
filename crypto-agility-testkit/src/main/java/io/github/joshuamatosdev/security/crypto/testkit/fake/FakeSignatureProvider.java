package io.github.joshuamatosdev.security.crypto.testkit.fake;

import io.github.joshuamatosdev.security.crypto.api.KeyHandle;
import io.github.joshuamatosdev.security.crypto.api.SignatureAlgorithm;
import io.github.joshuamatosdev.security.crypto.api.SignatureProvider;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * Deterministic fake provider for consumer tests.
 *
 * <p>This is not cryptography and must never be used as a production provider.
 */
public final class FakeSignatureProvider implements SignatureProvider {

    private final SignatureAlgorithm algorithm;

    public FakeSignatureProvider(final SignatureAlgorithm algorithm) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm must not be null");
    }

    @Override
    public SignatureAlgorithm algorithm() {
        return algorithm;
    }

    @Override
    public KeyHandle generateKey(final String keyId) {
        return new FakeKeyHandle(algorithm, keyId);
    }

    @Override
    public boolean verify(final byte[] publicKey, final byte[] payload, final byte[] signature) {
        if (publicKey == null || payload == null || signature == null) {
            return false;
        }
        return MessageDigest.isEqual(signature, digest(publicKey, payload));
    }

    private record FakeKeyHandle(SignatureAlgorithm algorithm, String keyId) implements KeyHandle {

        private FakeKeyHandle {
            Objects.requireNonNull(algorithm, "algorithm must not be null");
            Objects.requireNonNull(keyId, "keyId must not be null");
        }

        @Override
        public byte[] publicKey() {
            return ("fake-public-key:" + algorithm.joseAlg() + ":" + keyId).getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public byte[] sign(final byte[] payload) {
            Objects.requireNonNull(payload, "payload must not be null");
            return digest(publicKey(), payload);
        }
    }

    private static byte[] digest(final byte[] publicKey, final byte[] payload) {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(publicKey);
            digest.update((byte) 0);
            digest.update(payload);
            return digest.digest();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }
}
