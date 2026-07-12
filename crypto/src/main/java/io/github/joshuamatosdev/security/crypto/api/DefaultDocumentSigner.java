package io.github.joshuamatosdev.security.crypto.api;

import io.github.joshuamatosdev.security.shared.RequiredText;
import java.util.Objects;

/** Default-key signing capability layered over the explicit-key {@link DocumentSigner}. */
public final class DefaultDocumentSigner {

    private final DocumentSigner signer;
    private final SignatureAlgorithm algorithm;
    private final KeyHandleResolver keyHandleResolver;
    private final KeyIdStrategy keyIdStrategy;

    public DefaultDocumentSigner(
            final DocumentSigner signer,
            final SignatureAlgorithm algorithm,
            final KeyHandleResolver keyHandleResolver,
            final KeyIdStrategy keyIdStrategy) {
        this.signer = Objects.requireNonNull(signer, "signer must not be null");
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm must not be null");
        this.keyHandleResolver = Objects.requireNonNull(keyHandleResolver, "keyHandleResolver must not be null");
        this.keyIdStrategy = Objects.requireNonNull(keyIdStrategy, "keyIdStrategy must not be null");
    }

    /** Resolves the current configured key and signs the payload. */
    public SignedDocument sign(final byte[] payload) {
        final String keyId = requireKeyId(keyIdStrategy.currentKeyId(algorithm), "default key id");
        final KeyHandle key = Objects.requireNonNull(
                keyHandleResolver.resolve(algorithm, keyId), "keyHandleResolver must not return null");
        if (!algorithm.equals(key.algorithm())) {
            throw new IllegalStateException(
                    "Resolved default key algorithm must match configured default algorithm");
        }
        if (!keyId.equals(requireKeyId(key.keyId(), "resolved default key id"))) {
            throw new IllegalStateException("Resolved default key id must match current key id");
        }
        return signer.sign(key, payload);
    }

    private static String requireKeyId(final String value, final String field) {
        Objects.requireNonNull(value, field + " must not be null");
        RequiredText.violation(value).ifPresent(violation -> {
            throw new IllegalStateException(field + " " + violation);
        });
        return value;
    }
}
