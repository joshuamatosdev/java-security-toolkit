package io.github.joshuamatosdev.security.crypto.api;

import io.github.joshuamatosdev.security.crypto.internal.DefaultSignatureEnvelopeCodec;
import java.util.Objects;

/**
 * Algorithm-agnostic document signing and verification facade.
 *
 * <p>Callers can sign with an explicit {@link KeyHandle}, or configure a default algorithm, key-id
 * strategy, and key resolver for dependency-injected application code.
 */
public final class DocumentSigner {

    private final SignatureProviderRegistry registry;
    private final SignatureAlgorithm defaultAlgorithm;
    private final KeyHandleResolver keyHandleResolver;
    private final KeyIdStrategy keyIdStrategy;
    private final SignatureEnvelopeCodec envelopeCodec;
    private final SignatureAuditSink auditSink;

    /** Creates a signer with explicit-key signing only and the default envelope codec. */
    public DocumentSigner(final SignatureProviderRegistry registry) {
        this(registry, null, null, null, new DefaultSignatureEnvelopeCodec(), SignatureAuditSink.noop());
    }

    /**
     * Creates a signer with configurable default-key signing.
     *
     * <p>Passing {@code null} for default signing collaborators is allowed, but {@link #sign(byte[])}
     * will fail fast until all three are supplied.
     */
    public DocumentSigner(
            final SignatureProviderRegistry registry,
            final SignatureAlgorithm defaultAlgorithm,
            final KeyHandleResolver keyHandleResolver,
            final KeyIdStrategy keyIdStrategy,
            final SignatureEnvelopeCodec envelopeCodec,
            final SignatureAuditSink auditSink) {
        this.registry = Objects.requireNonNull(registry, "registry must not be null");
        this.defaultAlgorithm = defaultAlgorithm;
        this.keyHandleResolver = keyHandleResolver;
        this.keyIdStrategy = keyIdStrategy;
        this.envelopeCodec = Objects.requireNonNull(envelopeCodec, "envelopeCodec must not be null");
        this.auditSink = Objects.requireNonNull(auditSink, "auditSink must not be null");
    }

    /** Signs a payload with the configured default algorithm and current key id. */
    public SignedDocument sign(final byte[] payload) {
        if (defaultAlgorithm == null || keyHandleResolver == null || keyIdStrategy == null) {
            throw new IllegalStateException(
                    "Default signing requires a default algorithm, key handle resolver, and key id strategy");
        }
        final String keyId = requireNonBlank(keyIdStrategy.currentKeyId(defaultAlgorithm), "default key id");
        final KeyHandle key = keyHandleResolver.resolve(defaultAlgorithm, keyId);
        requireDefaultKey(defaultAlgorithm, keyId, key);
        return sign(key, payload);
    }

    /** Signs a payload with an explicit key handle. */
    public SignedDocument sign(final KeyHandle key, final byte[] payload) {
        Objects.requireNonNull(key, "key must not be null");
        Objects.requireNonNull(payload, "payload must not be null");

        final String alg = key.algorithm().joseAlg();
        final String keyId = key.keyId();
        final byte[] publicKey = key.publicKey();
        try {
            final byte[] signature = key.sign(envelopeCodec.signingInput(alg, keyId, publicKey, payload));
            final SignedDocument document = new SignedDocument(alg, keyId, publicKey, payload, signature);
            record(SignatureAuditEvent.Operation.SIGN, alg, keyId, true, "signed");
            return document;
        } catch (RuntimeException ex) {
            record(SignatureAuditEvent.Operation.SIGN, alg, keyId, false, ex.getClass().getSimpleName());
            throw ex;
        }
    }

    /** Backwards-readable alias for {@link #sign(KeyHandle, byte[])}. */
    public SignedDocument seal(final KeyHandle key, final byte[] payload) {
        return sign(key, payload);
    }

    /**
     * Verifies a signed document against the public key carried in the document.
     *
     * <p>This proves payload integrity under the embedded public key. Callers that need signer
     * authenticity must validate the public key against a trust anchor before trusting the payload.
     */
    public boolean verify(final SignedDocument document) {
        if (document == null) {
            record(SignatureAuditEvent.Operation.VERIFY, null, null, false, "document is null");
            return false;
        }
        final SignatureAlgorithm algorithm;
        try {
            algorithm = SignatureAlgorithm.fromJoseAlg(document.alg());
        } catch (IllegalArgumentException ex) {
            record(SignatureAuditEvent.Operation.VERIFY, document.alg(), document.keyId(), false, "unsupported alg");
            return false;
        }

        final SignatureProvider provider;
        try {
            provider = registry.resolve(algorithm);
        } catch (IllegalArgumentException ex) {
            record(SignatureAuditEvent.Operation.VERIFY, document.alg(), document.keyId(), false, "provider missing");
            return false;
        }

        final byte[] publicKey = document.publicKey();
        final boolean verified = provider.verify(
                publicKey,
                envelopeCodec.signingInput(document.alg(), document.keyId(), publicKey, document.payload()),
                document.signature());
        record(
                SignatureAuditEvent.Operation.VERIFY,
                document.alg(),
                document.keyId(),
                verified,
                verified ? "verified" : "verification failed");
        return verified;
    }

    private static void requireDefaultKey(
            final SignatureAlgorithm expectedAlgorithm, final String expectedKeyId, final KeyHandle key) {
        final String requiredKeyId = requireNonBlank(expectedKeyId, "default key id");
        Objects.requireNonNull(key, "keyHandleResolver must not return null");
        if (key.algorithm() != expectedAlgorithm) {
            throw new IllegalStateException(
                    "Resolved default key algorithm must match configured default algorithm");
        }
        if (!requiredKeyId.equals(requireNonBlank(key.keyId(), "resolved default key id"))) {
            throw new IllegalStateException("Resolved default key id must match current key id");
        }
    }

    private static String requireNonBlank(final String value, final String field) {
        Objects.requireNonNull(value, field + " must not be null");
        if (value.isBlank()) {
            throw new IllegalStateException(field + " must not be blank");
        }
        if (!value.equals(value.strip())) {
            throw new IllegalStateException(field + " must not include leading or trailing whitespace");
        }
        if (value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalStateException(field + " must not contain control characters");
        }
        return value;
    }

    private void record(
            final SignatureAuditEvent.Operation operation,
            final String alg,
            final String keyId,
            final boolean success,
            final String reason) {
        auditSink.record(new SignatureAuditEvent(operation, alg, keyId, success, reason));
    }
}
