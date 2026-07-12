package io.github.joshuamatosdev.security.crypto.api;

import io.github.joshuamatosdev.security.crypto.internal.DefaultSignatureEnvelopeCodec;
import io.github.joshuamatosdev.security.shared.RequiredText;
import java.util.Objects;

/**
 * Algorithm-agnostic document signing and verification facade.
 *
 * <p>Callers sign with an explicit {@link KeyHandle}. Applications that want a configured current
 * key use the separate {@link DefaultDocumentSigner} capability, so this type is never partially
 * configured.
 */
public final class DocumentSigner {

    private final SignatureProviderRegistry registry;
    private final SignatureEnvelopeCodec envelopeCodec;
    private final SignatureAuditSink auditSink;

    /** Creates a signer with explicit-key signing only and the default envelope codec. */
    public DocumentSigner(final SignatureProviderRegistry registry) {
        this(registry, new DefaultSignatureEnvelopeCodec(), SignatureAuditSink.noop());
    }

    /**
     * Creates an explicit-key signer and verifier with custom envelope and audit collaborators.
     */
    public DocumentSigner(
            final SignatureProviderRegistry registry,
            final SignatureEnvelopeCodec envelopeCodec,
            final SignatureAuditSink auditSink) {
        this.registry = Objects.requireNonNull(registry, "registry must not be null");
        this.envelopeCodec = Objects.requireNonNull(envelopeCodec, "envelopeCodec must not be null");
        this.auditSink = Objects.requireNonNull(auditSink, "auditSink must not be null");
    }

    /** Signs a payload with an explicit key handle. */
    public SignedDocument sign(final KeyHandle key, final byte[] payload) {
        Objects.requireNonNull(key, "key must not be null");
        Objects.requireNonNull(payload, "payload must not be null");

        final String alg = key.algorithm().joseAlg();
        // Validated before the try: the failure-path audit event below carries this key id, and
        // the event's own validation must never throw while recording a failure — that would both
        // lose the audit event and mask the root cause.
        final String keyId = RequiredText.require(key.keyId(), "keyId");
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

    /**
     * Verifies a signed document against the public key carried in the document.
     *
     * <p>This proves payload integrity under the embedded public key <em>only</em>. Callers that
     * need signer authenticity — the guarantee that the embedded key is one the deployment allows
     * to speak for the document's key id — must use {@link #verify(SignedDocument, TrustAnchor)}.
     */
    public SignatureVerification verify(final SignedDocument document) {
        if (document == null) {
            return reject(null, null, SignatureVerification.Failure.DOCUMENT_MISSING);
        }
        final SignatureAlgorithm algorithm = SignatureAlgorithm.fromJoseAlg(document.alg());

        if (!registry.hasProvider(algorithm)) {
            return reject(document.alg(), document.keyId(), SignatureVerification.Failure.PROVIDER_MISSING);
        }
        final SignatureProvider provider = registry.resolve(algorithm);

        final byte[] publicKey = document.publicKey();
        final boolean verified;
        try {
            verified = provider.verify(
                    publicKey,
                    envelopeCodec.signingInput(document.alg(), document.keyId(), publicKey, document.payload()),
                    document.signature());
        } catch (RuntimeException ex) {
            // Same audit posture as sign(): a provider or codec failure is recorded, then
            // propagated. Verification must not be the one operation that can fail unaudited.
            record(SignatureAuditEvent.Operation.VERIFY, document.alg(), document.keyId(), false,
                    ex.getClass().getSimpleName());
            throw ex;
        }
        if (!verified) {
            return reject(document.alg(), document.keyId(), SignatureVerification.Failure.INVALID_SIGNATURE);
        }
        record(SignatureAuditEvent.Operation.VERIFY, document.alg(), document.keyId(), true, "verified");
        return SignatureVerification.verified();
    }

    /**
     * Verifies a signed document <em>and</em> that its embedded public key is the one the trust
     * anchor allows for the document's key id — integrity plus signer authenticity.
     *
     * <p>The anchor is consulted first and fails closed: a document whose embedded key the anchor
     * does not trust is rejected (audited as {@code untrusted key}) before any signature
     * computation, so a key-substitution forgery — tampered payload re-signed under an
     * attacker-chosen key — never reaches cryptographic verification at all.
     */
    public SignatureVerification verify(final SignedDocument document, final TrustAnchor trustAnchor) {
        Objects.requireNonNull(trustAnchor, "trustAnchor must not be null");
        if (document == null) {
            return reject(null, null, SignatureVerification.Failure.DOCUMENT_MISSING);
        }
        final boolean trusted;
        try {
            trusted = trustAnchor.trusts(document.keyId(), document.publicKey());
        } catch (RuntimeException ex) {
            // Anchors backed by KMS or key-directory lookups can fail at runtime; record before
            // propagating so the anchored path keeps the same audit completeness as verify().
            record(SignatureAuditEvent.Operation.VERIFY, document.alg(), document.keyId(), false,
                    ex.getClass().getSimpleName());
            throw ex;
        }
        if (!trusted) {
            return reject(document.alg(), document.keyId(), SignatureVerification.Failure.UNTRUSTED_KEY);
        }
        return verify(document);
    }

    private SignatureVerification reject(
            final String alg,
            final String keyId,
            final SignatureVerification.Failure failure) {
        record(SignatureAuditEvent.Operation.VERIFY, alg, keyId, false, failure.auditReason());
        return SignatureVerification.rejected(failure);
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
