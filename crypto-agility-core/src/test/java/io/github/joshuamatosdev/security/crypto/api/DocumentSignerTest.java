package io.github.joshuamatosdev.security.crypto.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.crypto.jca.JcaSignatureProviders;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class DocumentSignerTest {

    private static final byte[] DOCUMENT = "transcript of record".getBytes(StandardCharsets.UTF_8);

    private final SignatureProviderRegistry registry =
            new SignatureProviderRegistry(
                    List.of(
                            JcaSignatureProviders.ed25519(),
                            JcaSignatureProviders.ecdsaP256(),
                            JcaSignatureProviders.postQuantumPlaceholder()));
    private final DocumentSigner signer = new DocumentSigner(registry);

    @Test
    void signAndVerifyRoundTripUnderEveryAlgorithm() {
        for (final SignatureAlgorithm algorithm : SignatureAlgorithm.values()) {
            final KeyHandle key = registry.resolve(algorithm).generateKey("key-" + algorithm.name());

            final SignedDocument signed = signer.sign(key, DOCUMENT);

            assertThat(signer.verify(signed)).isTrue();
            assertThat(signed.alg()).isEqualTo(algorithm.joseAlg());
            assertThat(signed.keyId()).isEqualTo("key-" + algorithm.name());
        }
    }

    @Test
    void sealAliasUsesTheSameEnvelopeAsSign() {
        final KeyHandle key = registry.resolve(SignatureAlgorithm.ED25519).generateKey("k1");

        assertThat(signer.verify(signer.seal(key, DOCUMENT))).isTrue();
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
                        signed.signature())))
                .isFalse();
        final byte[] tamperedSignature = signed.signature();
        tamperedSignature[tamperedSignature.length - 1] ^= 0x01;
        assertThat(signer.verify(new SignedDocument(
                        signed.alg(), signed.keyId(), signed.publicKey(), signed.payload(), tamperedSignature)))
                .isFalse();
        assertThat(signer.verify(new SignedDocument(
                        signed.alg(), "attacker-key-id", signed.publicKey(), signed.payload(), signed.signature())))
                .isFalse();
        assertThat(signer.verify(new SignedDocument(
                        SignatureAlgorithm.ECDSA_P256.joseAlg(),
                        signed.keyId(),
                        signed.publicKey(),
                        signed.payload(),
                        signed.signature())))
                .isFalse();
    }

    @Test
    void defaultSigningUsesConfiguredAlgorithmResolverAndKeyIdStrategy() {
        final KeyHandle key = registry.resolve(SignatureAlgorithm.ED25519).generateKey("default-k1");
        final DocumentSigner defaultSigner = new DocumentSigner(
                registry,
                SignatureAlgorithm.ED25519,
                (algorithm, keyId) -> key,
                algorithm -> "default-k1",
                (alg, keyId, publicKey, payload) -> new io.github.joshuamatosdev.security.crypto.internal
                        .DefaultSignatureEnvelopeCodec()
                        .signingInput(alg, keyId, publicKey, payload),
                SignatureAuditSink.noop());

        final SignedDocument signed = defaultSigner.sign(DOCUMENT);

        assertThat(signed.keyId()).isEqualTo("default-k1");
        assertThat(defaultSigner.verify(signed)).isTrue();
    }

    @Test
    void defaultSigningFailsFastUntilDefaultCollaboratorsAreConfigured() {
        assertThatThrownBy(() -> signer.sign(DOCUMENT))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Default signing requires");
    }

    @Test
    void verifyRejectsUnknownOrMissingProvidersWithoutThrowing() {
        final SignedDocument signed =
                signer.sign(registry.resolve(SignatureAlgorithm.ED25519).generateKey("k1"), DOCUMENT);
        final SignedDocument unknownAlgorithm =
                new SignedDocument("none", signed.keyId(), signed.publicKey(), signed.payload(), signed.signature());
        final DocumentSigner emptySigner = new DocumentSigner(new SignatureProviderRegistry(List.of()));

        assertThat(signer.verify(unknownAlgorithm)).isFalse();
        assertThat(emptySigner.verify(signed)).isFalse();
    }

    @Test
    void verifyDoesNotHideProviderProgrammingErrors() {
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
        final DocumentSigner brokenSigner =
                new DocumentSigner(new SignatureProviderRegistry(List.of(brokenProvider)));

        assertThatThrownBy(() -> brokenSigner.verify(signed))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("provider invariant failed");
    }

    @Test
    void auditSinkReceivesSignAndVerifyEvents() {
        final List<SignatureAuditEvent> events = new ArrayList<>();
        final DocumentSigner audited = new DocumentSigner(
                registry,
                null,
                null,
                null,
                new io.github.joshuamatosdev.security.crypto.internal.DefaultSignatureEnvelopeCodec(),
                events::add);
        final SignedDocument signed =
                audited.sign(registry.resolve(SignatureAlgorithm.ED25519).generateKey("k1"), DOCUMENT);

        assertThat(audited.verify(signed)).isTrue();
        assertThat(events)
                .extracting(SignatureAuditEvent::operation)
                .containsExactly(SignatureAuditEvent.Operation.SIGN, SignatureAuditEvent.Operation.VERIFY);
    }
}
