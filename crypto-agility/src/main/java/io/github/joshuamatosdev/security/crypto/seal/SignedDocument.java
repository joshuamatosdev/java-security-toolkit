package io.github.joshuamatosdev.security.crypto.seal;

import java.util.Arrays;
import java.util.Objects;

/**
 * A document together with the signature over it and everything a verifier needs to check it: the
 * {@code alg} wire identifier, the versioned key id, and the encoded public key.
 *
 * <p>The {@code alg} field is what makes verification algorithm-agnostic — a verifier reads it,
 * resolves the matching provider from the registry, and checks the signature, without the call site
 * naming any algorithm. The byte-array components are defensively copied on the way in and out so an
 * instance is genuinely immutable.
 *
 * @param alg the JOSE {@code alg} header value the document was signed under
 * @param keyId the versioned identifier of the signing key
 * @param publicKey the encoded public key to verify against
 * @param payload the signed document bytes
 * @param signature the signature bytes
 *
 * <p>Why this exists: document sealing is the stable call site that proves signature algorithms
 * can be swapped behind the same interface.
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
            throw new IllegalArgumentException(
                    field + " must not contain leading or trailing whitespace");
        }
        if (value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(field + " must not contain control characters");
        }
        return value;
    }
}
