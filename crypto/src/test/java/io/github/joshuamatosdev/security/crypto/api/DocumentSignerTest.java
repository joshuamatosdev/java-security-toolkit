package io.github.joshuamatosdev.security.crypto.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.crypto.internal.DefaultSignatureEnvelopeCodec;
import io.github.joshuamatosdev.security.crypto.jca.JcaSignatureProviders;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class DocumentSignerTest {

    private static final byte[] DOCUMENT = "transcript of record".getBytes(StandardCharsets.UTF_8);

    private final SignatureProviderRegistry registry =
            new SignatureProviderRegistry(
                    List.of(JcaSignatureProviders.ed25519(), JcaSignatureProviders.ecdsaP256()));
    private final DocumentSigner signer = new DocumentSigner(registry);

    @Test
    void signAndVerifyRoundTripUnderEveryAlgorithm() {
        for (final SignatureAlgorithm algorithm :
                List.of(SignatureAlgorithm.ED25519, SignatureAlgorithm.ECDSA_P256)) {
            final String keyId = "key-" + algorithm.joseAlg();
            final KeyHandle key = registry.resolve(algorithm).generateKey(keyId);

            final SignedDocument signed = signer.sign(key, DOCUMENT);

            assertThat(signer.verify(signed).isVerified()).isTrue();
            assertThat(signed.alg()).isEqualTo(algorithm.joseAlg());
            assertThat(signed.keyId()).isEqualTo(keyId);
        }
    }

    @Test
    void trustAnchoredVerifyAcceptsTheDeploymentsPinnedKey() {
        final KeyHandle key = registry.resolve(SignatureAlgorithm.ED25519).generateKey("k1");
        final SignedDocument signed = signer.sign(key, DOCUMENT);
        final TrustAnchor anchor = TrustAnchor.pinnedKeys(Map.of("k1", key.publicKey()));

        assertThat(signer.verify(signed, anchor).isVerified()).isTrue();
    }

    @Test
    void trustAnchoredVerifyDefeatsKeySubstitution() {
        // The attack the embedded-key verify cannot see: tamper the payload, re-sign it with an
        // attacker-generated key, embed the attacker's public key under the SAME key id.
        final KeyHandle legitimate = registry.resolve(SignatureAlgorithm.ED25519).generateKey("k1");
        final KeyHandle attacker = registry.resolve(SignatureAlgorithm.ED25519).generateKey("k1");
        final SignedDocument forged =
                signer.sign(attacker, "transcript of fraud".getBytes(StandardCharsets.UTF_8));
        final TrustAnchor anchor = TrustAnchor.pinnedKeys(Map.of("k1", legitimate.publicKey()));

        assertThat(signer.verify(forged).isVerified())
                .as("integrity-only verify accepts the forgery — this is the documented gap")
                .isTrue();
        assertThat(signer.verify(forged, anchor).isVerified())
                .as("the anchored verify rejects the untrusted key before any signature check")
                .isFalse();
    }

    @Test
    void trustAnchoredVerifyRejectsUnknownKeyIds() {
        final KeyHandle key = registry.resolve(SignatureAlgorithm.ED25519).generateKey("k2");
        final SignedDocument signed = signer.sign(key, DOCUMENT);
        final TrustAnchor anchor = TrustAnchor.pinnedKeys(Map.of("k1", key.publicKey()));

        assertThat(signer.verify(signed, anchor).isVerified()).isFalse();
    }

    @Test
    void trustAnchoredVerifyAuditsTheUntrustedKeyReason() {
        final List<SignatureAuditEvent> events = new ArrayList<>();
        final DocumentSigner audited =
                new DocumentSigner(registry, new DefaultSignatureEnvelopeCodec(), events::add);
        final KeyHandle key = registry.resolve(SignatureAlgorithm.ED25519).generateKey("k1");
        final SignedDocument signed = audited.sign(key, DOCUMENT);

        assertThat(audited.verify(signed, TrustAnchor.pinnedKeys(Map.of())).isVerified()).isFalse();
        assertThat(events.getLast().reason()).isEqualTo("untrusted key");
    }

    @Test
    void verifyRejectsTamperedPayloadSignatureKeyIdAndAlgorithm() {
        final SignedDocument signed =
                signer.sign(registry.resolve(SignatureAlgorithm.ED25519).generateKey("k1"), DOCUMENT);

        assertThat(signer.verify(new SignedDocument(
                        signed.alg(),
                        signed.keyId(),
                        signed.publicKey(),
                        "transcript of fraud".getBytes(StandardCharsets.UTF_8),
                        signed.signature())).isVerified())
                .isFalse();
        final byte[] tamperedSignature = signed.signature();
        tamperedSignature[tamperedSignature.length - 1] ^= 0x01;
        assertThat(signer.verify(new SignedDocument(
                        signed.alg(), signed.keyId(), signed.publicKey(), signed.payload(), tamperedSignature))
                        .isVerified())
                .isFalse();
        assertThat(signer.verify(new SignedDocument(
                        signed.alg(), "attacker-key-id", signed.publicKey(), signed.payload(), signed.signature()))
                        .isVerified())
                .isFalse();
        assertThat(signer.verify(new SignedDocument(
                        SignatureAlgorithm.ECDSA_P256.joseAlg(),
                        signed.keyId(),
                        signed.publicKey(),
                        signed.payload(),
                        signed.signature())).isVerified())
                .isFalse();
    }

    @Test
    void defaultSigningUsesConfiguredAlgorithmResolverAndKeyIdStrategy() {
        final KeyHandle key = registry.resolve(SignatureAlgorithm.ED25519).generateKey("default-k1");
        final DefaultDocumentSigner defaultSigner = new DefaultDocumentSigner(
                signer,
                SignatureAlgorithm.ED25519,
                (algorithm, keyId) -> key,
                algorithm -> "default-k1");

        final SignedDocument signed = defaultSigner.sign(DOCUMENT);

        assertThat(signed.keyId()).isEqualTo("default-k1");
        assertThat(signer.verify(signed).isVerified()).isTrue();
    }

    @Test
    void defaultSigningRejectsResolverKeysForTheWrongAlgorithm() {
        final KeyHandle wrongAlgorithm = registry.resolve(SignatureAlgorithm.ECDSA_P256).generateKey("default-k1");
        final DefaultDocumentSigner defaultSigner =
                defaultSigner(SignatureAlgorithm.ED25519, "default-k1", wrongAlgorithm);

        assertThatThrownBy(() -> defaultSigner.sign(DOCUMENT))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Resolved default key algorithm must match configured default algorithm");
    }

    @Test
    void defaultSigningRejectsResolverKeysForTheWrongKeyId() {
        final KeyHandle wrongKeyId = registry.resolve(SignatureAlgorithm.ED25519).generateKey("rotated-k2");
        final DefaultDocumentSigner defaultSigner =
                defaultSigner(SignatureAlgorithm.ED25519, "default-k1", wrongKeyId);

        assertThatThrownBy(() -> defaultSigner.sign(DOCUMENT))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Resolved default key id must match current key id");
    }

    @Test
    void defaultSigningRejectsBlankCurrentKeyIdBeforeResolvingAKey() {
        final DefaultDocumentSigner defaultSigner = new DefaultDocumentSigner(
                signer,
                SignatureAlgorithm.ED25519,
                (algorithm, keyId) -> {
                    throw new AssertionError("key resolver should not be called for a blank key id");
                },
                algorithm -> " ");

        assertThatThrownBy(() -> defaultSigner.sign(DOCUMENT))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("default key id must not be blank");
    }

    @Test
    void verifyRejectsUnknownOrMissingProvidersWithoutThrowing() {
        final SignedDocument signed =
                signer.sign(registry.resolve(SignatureAlgorithm.ED25519).generateKey("k1"), DOCUMENT);
        final SignedDocument unknownAlgorithm =
                new SignedDocument("none", signed.keyId(), signed.publicKey(), signed.payload(), signed.signature());
        final DocumentSigner emptySigner = new DocumentSigner(new SignatureProviderRegistry(List.of()));

        assertThat(signer.verify(unknownAlgorithm))
                .isEqualTo(SignatureVerification.rejected(SignatureVerification.Failure.PROVIDER_MISSING));
        assertThat(emptySigner.verify(signed))
                .isEqualTo(SignatureVerification.rejected(SignatureVerification.Failure.PROVIDER_MISSING));
    }

    @Test
    void verifyDoesNotHideProviderProgrammingErrorsAndStillAuditsThem() {
        final SignedDocument signed =
                signer.sign(registry.resolve(SignatureAlgorithm.ED25519).generateKey("k1"), DOCUMENT);
        final SignatureProvider brokenProvider =
                new SignatureProvider() {
                    @Override
                    public SignatureAlgorithm algorithm() {
                        return SignatureAlgorithm.ED25519;
                    }

                    @Override
                    public KeyHandle generateKey(final String keyId) {
                        throw new UnsupportedOperationException("not needed");
                    }

                    @Override
                    public boolean verify(final byte[] publicKey, final byte[] payload, final byte[] signature) {
                        throw new IllegalArgumentException("provider invariant failed");
                    }
                };
        final List<SignatureAuditEvent> events = new ArrayList<>();
        final DocumentSigner brokenSigner = new DocumentSigner(
                new SignatureProviderRegistry(List.of(brokenProvider)),
                new DefaultSignatureEnvelopeCodec(),
                events::add);

        assertThatThrownBy(() -> brokenSigner.verify(signed))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("provider invariant failed");
        // Verification failures must reach the audit pipeline exactly as signing failures do.
        assertThat(events.getLast().operation()).isEqualTo(SignatureAuditEvent.Operation.VERIFY);
        assertThat(events.getLast().success()).isFalse();
        assertThat(events.getLast().reason()).isEqualTo("IllegalArgumentException");
    }

    @Test
    void signRejectsMalformedKeyIdsUpFrontWithoutMaskingOrPhantomAuditFailures() {
        final KeyHandle real = registry.resolve(SignatureAlgorithm.ED25519).generateKey("k1");
        final KeyHandle paddedKeyId = new KeyHandle() {
            @Override
            public String keyId() {
                return " k1 ";
            }

            @Override
            public SignatureAlgorithm algorithm() {
                return real.algorithm();
            }

            @Override
            public byte[] publicKey() {
                return real.publicKey();
            }

            @Override
            public byte[] sign(final byte[] payload) {
                return real.sign(payload);
            }
        };
        final List<SignatureAuditEvent> events = new ArrayList<>();
        final DocumentSigner audited =
                new DocumentSigner(registry, new DefaultSignatureEnvelopeCodec(), events::add);

        // Before the up-front validation, the malformed key id detonated inside the failure
        // recording itself: the audit event's validation replaced the root cause and delivered
        // nothing to the sink. Now the caller-contract violation fails fast with its own message.
        assertThatThrownBy(() -> audited.sign(paddedKeyId, DOCUMENT))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("keyId must not include leading or trailing whitespace");
        assertThat(events).isEmpty();
    }

    @Test
    void auditSinkReceivesSignAndVerifyEvents() {
        final List<SignatureAuditEvent> events = new ArrayList<>();
        final DocumentSigner audited =
                new DocumentSigner(registry, new DefaultSignatureEnvelopeCodec(), events::add);
        final SignedDocument signed =
                audited.sign(registry.resolve(SignatureAlgorithm.ED25519).generateKey("k1"), DOCUMENT);

        assertThat(audited.verify(signed).isVerified()).isTrue();
        assertThat(events)
                .extracting(SignatureAuditEvent::operation)
                .containsExactly(SignatureAuditEvent.Operation.SIGN, SignatureAuditEvent.Operation.VERIFY);
    }

    private DefaultDocumentSigner defaultSigner(
            final SignatureAlgorithm algorithm, final String currentKeyId, final KeyHandle resolvedKey) {
        return new DefaultDocumentSigner(
                signer,
                algorithm,
                (requestedAlgorithm, requestedKeyId) -> resolvedKey,
                requestedAlgorithm -> currentKeyId);
    }
}
