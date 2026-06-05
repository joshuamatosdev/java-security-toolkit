package io.github.joshuamatosdev.security.crypto.api;

import java.util.Arrays;
import java.util.Objects;

/**
 * Payload, signature, and metadata required to verify a signed document.
 *
 * @param alg wire algorithm identifier
 * @param keyId versioned signing key id
 * @param publicKey encoded public key
 * @param payload signed payload bytes
 * @param signature signature bytes
 */
public record SignedDocument(
        String alg, String keyId, byte[] publicKey, byte[] payload, byte[] signature) {

    public SignedDocument {
        alg = requireNonBlank(alg, "alg");
        keyId = requireNonBlank(keyId, "keyId");
        publicKey = Objects.requireNonNull(publicKey, "publicKey must not be null").clone();
        payload = Objects.requireNonNull(payload, "payload must not be null").clone();
        signature = Objects.requireNonNull(signature, "signature must not be null").clone();
    }

    @Override
    public byte[] publicKey() {
        return publicKey.clone();
    }

    @Override
    public byte[] payload() {
        return payload.clone();
    }

    @Override
    public byte[] signature() {
        return signature.clone();
    }

    @Override
    public boolean equals(final Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof SignedDocument document)) {
            return false;
        }
        return alg.equals(document.alg)
                && keyId.equals(document.keyId)
                && Arrays.equals(publicKey, document.publicKey)
                && Arrays.equals(payload, document.payload)
                && Arrays.equals(signature, document.signature);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(alg, keyId);
        result = 31 * result + Arrays.hashCode(publicKey);
        result = 31 * result + Arrays.hashCode(payload);
        result = 31 * result + Arrays.hashCode(signature);
        return result;
    }

    private static String requireNonBlank(final String value, final String field) {
        Objects.requireNonNull(value, field + " must not be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        if (!value.equals(value.strip())) {
            throw new IllegalArgumentException(field + " must not contain leading or trailing whitespace");
        }
        if (value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(field + " must not contain control characters");
        }
        return value;
    }
}
