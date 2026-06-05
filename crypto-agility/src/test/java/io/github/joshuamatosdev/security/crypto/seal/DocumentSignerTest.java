package io.github.joshuamatosdev.security.crypto.seal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.crypto.key.KeyHandle;
import io.github.joshuamatosdev.security.crypto.provider.SignatureProvider;
import io.github.joshuamatosdev.security.crypto.provider.SignatureProviders;
import io.github.joshuamatosdev.security.crypto.registry.SignatureAlgorithm;
import io.github.joshuamatosdev.security.crypto.registry.SignatureProviderRegistry;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * The agility property under test: one {@link DocumentSigner} call site seals and verifies under
 * every algorithm — classical and post-quantum — with no per-algorithm code.
 *
 * <p>Why this is important to test: algorithm migration depends on identical signing semantics
 * across providers and robust rejection of invalid key or signature material.
 */
class DocumentSignerTest {

    private static final byte[] DOCUMENT = "transcript of record".getBytes(StandardCharsets.UTF_8);

    private final SignatureProviderRegistry registry =
            new SignatureProviderRegistry(
                    List.of(
                            SignatureProviders.ed25519(),
                            SignatureProviders.ecdsaP256(),
                            SignatureProviders.postQuantumPlaceholder()));
    private final DocumentSigner signer = new DocumentSigner(registry);

    private KeyHandle keyFor(final SignatureAlgorithm algorithm) {
        return registry.resolve(algorithm).generateKey("key-" + algorithm.name());
    }

    @ParameterizedTest
    @EnumSource(SignatureAlgorithm.class)
    void sealAndVerifyRoundTripUnderEveryAlgorithm(final SignatureAlgorithm algorithm) {
        final KeyHandle key = keyFor(algorithm);

        // These two lines are the entire call site — identical for every algorithm.
        final SignedDocument sealed = signer.seal(key, DOCUMENT);
        final boolean verified = signer.verify(sealed);

        assertThat(verified).isTrue();
        assertThat(sealed.alg()).isEqualTo(algorithm.joseAlg());
        assertThat(sealed.keyId()).isEqualTo("key-" + algorithm.name());
    }

    @Test
    void swappingTheKeyChangesTheWireAlgorithmWithoutChangingTheCallSite() {
        final SignedDocument classical = signer.seal(keyFor(SignatureAlgorithm.ED25519), DOCUMENT);
        final SignedDocument postQuantum = signer.seal(keyFor(SignatureAlgorithm.ML_DSA_44), DOCUMENT);

        // Same seal() call, different key handed in — the produced alg follows the key.
        assertThat(classical.alg()).isEqualTo("EdDSA");
        assertThat(postQuantum.alg()).isEqualTo("ML-DSA-44");
        assertThat(signer.verify(classical)).isTrue();
        assertThat(signer.verify(postQuantum)).isTrue();
    }

    @Test
    void verifyRejectsATamperedDocument() {
        final SignedDocument sealed = signer.seal(keyFor(SignatureAlgorithm.ECDSA_P256), DOCUMENT);
        final SignedDocument tampered =
                new SignedDocument(
                        sealed.alg(),
                        sealed.keyId(),
                        sealed.publicKey(),
                        "transcript of fraud".getBytes(StandardCharsets.UTF_8),
                        sealed.signature());

        assertThat(signer.verify(tampered)).isFalse();
    }

    @Test
    void verifyRejectsADocumentWhoseAlgLabelWasSwapped() {
        final SignedDocument sealed = signer.seal(keyFor(SignatureAlgorithm.ED25519), DOCUMENT);

        // Relabel an Ed25519-signed document as ECDSA: the ECDSA provider cannot parse the Ed25519
        // public key, so the forgery is rejected rather than silently accepted.
        final SignedDocument relabeled =
                new SignedDocument(
                        SignatureAlgorithm.ECDSA_P256.joseAlg(),
                        sealed.keyId(),
                        sealed.publicKey(),
                        sealed.payload(),
                        sealed.signature());

        assertThat(signer.verify(relabeled)).isFalse();
    }

    @Test
    void verifyRejectsADocumentWhoseKeyIdWasTampered() {
        final SignedDocument sealed = signer.seal(keyFor(SignatureAlgorithm.ED25519), DOCUMENT);
        final SignedDocument tamperedKeyId =
                new SignedDocument(
                        sealed.alg(),
                        "attacker-key-id",
                        sealed.publicKey(),
                        sealed.payload(),
                        sealed.signature());

        assertThat(signer.verify(tamperedKeyId)).isFalse();
    }

    @Test
    void signedDocumentEqualityUsesByteContentRatherThanArrayIdentity() {
        final SignedDocument sealed = signer.seal(keyFor(SignatureAlgorithm.ED25519), DOCUMENT);
        final SignedDocument sameEnvelope =
                new SignedDocument(
                        sealed.alg(),
                        sealed.keyId(),
                        sealed.publicKey(),
                        sealed.payload(),
                        sealed.signature());

        assertThat(sameEnvelope).isEqualTo(sealed);
        assertThat(sameEnvelope.hashCode()).isEqualTo(sealed.hashCode());
    }

    @Test
    void verifyRejectsUnknownAlgLabelWithoutThrowing() {
        final SignedDocument sealed = signer.seal(keyFor(SignatureAlgorithm.ED25519), DOCUMENT);
        final SignedDocument unknownAlgorithm =
                new SignedDocument(
                        "none",
                        sealed.keyId(),
                        sealed.publicKey(),
                        sealed.payload(),
                        sealed.signature());

        assertThat(signer.verify(unknownAlgorithm)).isFalse();
    }

    @Test
    void verifyRejectsKnownAlgLabelWhenNoProviderIsRegisteredWithoutThrowing() {
        final SignedDocument sealed = signer.seal(keyFor(SignatureAlgorithm.ECDSA_P256), DOCUMENT);
        final DocumentSigner classicalOnlySigner =
                new DocumentSigner(new SignatureProviderRegistry(List.of(SignatureProviders.ed25519())));

        assertThat(classicalOnlySigner.verify(sealed)).isFalse();
    }

    @Test
    void constructorRejectsANullRegistry() {
        assertThatThrownBy(() -> new DocumentSigner(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("registry must not be null");
    }

    @Test
    void verifyDoesNotHideProviderProgrammingErrors() {
        final SignedDocument sealed = signer.seal(keyFor(SignatureAlgorithm.ED25519), DOCUMENT);
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
                    public boolean verify(
                            final byte[] publicKey, final byte[] payload, final byte[] signature) {
                        throw new IllegalArgumentException("provider invariant failed");
                    }
                };
        final DocumentSigner brokenSigner =
                new DocumentSigner(new SignatureProviderRegistry(List.of(brokenProvider)));

        assertThatThrownBy(() -> brokenSigner.verify(sealed))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("provider invariant failed");
    }

    @Test
    void verifyRejectsANullOrMalformedEnvelopeWithoutThrowing() {
        assertThat(signer.verify(null)).isFalse();

        assertThatThrownBy(
                        () ->
                                new SignedDocument(
                                        null,
                                        "k1",
                                        new byte[] {1},
                                        DOCUMENT,
                                        new byte[] {2}))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("alg must not be null");
    }

    @Test
    void signedDocumentRejectsBlankRequiredMetadata() {
        assertThatThrownBy(
                        () -> new SignedDocument(" ", "k1", new byte[] {1}, DOCUMENT, new byte[] {2}))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("alg must not be blank");

        assertThatThrownBy(
                        () -> new SignedDocument("EdDSA", " ", new byte[] {1}, DOCUMENT, new byte[] {2}))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("keyId must not be blank");
    }

    @Test
    void signedDocumentRejectsEdgePaddedRequiredMetadata() {
        assertThatThrownBy(
                        () -> new SignedDocument(" EdDSA", "k1", new byte[] {1}, DOCUMENT, new byte[] {2}))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("alg must not contain leading or trailing whitespace");

        assertThatThrownBy(
                        () -> new SignedDocument("EdDSA", "k1 ", new byte[] {1}, DOCUMENT, new byte[] {2}))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("keyId must not contain leading or trailing whitespace");
    }

    @Test
    void signedDocumentRejectsControlCharactersInRequiredMetadata() {
        assertThatThrownBy(
                        () -> new SignedDocument("EdDSA\nforged", "k1", new byte[] {1}, DOCUMENT, new byte[] {2}))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("alg must not contain control characters");

        assertThatThrownBy(
                        () -> new SignedDocument("EdDSA", "k1\rforged", new byte[] {1}, DOCUMENT, new byte[] {2}))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("keyId must not contain control characters");
    }
}
