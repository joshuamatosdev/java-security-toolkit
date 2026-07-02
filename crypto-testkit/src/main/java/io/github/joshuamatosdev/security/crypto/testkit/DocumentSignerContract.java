package io.github.joshuamatosdev.security.crypto.testkit;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.crypto.api.DocumentSigner;
import io.github.joshuamatosdev.security.crypto.api.KeyHandle;
import io.github.joshuamatosdev.security.crypto.api.SignatureAlgorithm;
import io.github.joshuamatosdev.security.crypto.api.SignedDocument;
import io.github.joshuamatosdev.security.crypto.api.TrustAnchor;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Reusable contract tests for a configured {@link DocumentSigner}.
 *
 * <p>Implementers supply one signing key and a different registered/known algorithm id to prove
 * algorithm relabeling is rejected.
 */
public interface DocumentSignerContract {

    /** Configured signer under test. */
    DocumentSigner signer();

    /** Signing key under test. */
    KeyHandle signingKey();

    /** Algorithm id that differs from {@link #signingKey()}'s algorithm. */
    SignatureAlgorithm mismatchedAlgorithm();

    default byte[] contractDocument() {
        return "crypto signed document contract".getBytes(StandardCharsets.UTF_8);
    }

    @Test
    default void signedDocumentsVerify() {
        final SignedDocument signed = signer().sign(signingKey(), contractDocument());

        assertThat(signer().verify(signed)).isTrue();
    }

    @Test
    default void tamperedDocumentsFail() {
        final SignedDocument signed = signer().sign(signingKey(), contractDocument());
        final SignedDocument tampered = new SignedDocument(
                signed.alg(),
                signed.keyId(),
                signed.publicKey(),
                "crypto signed document tampered".getBytes(StandardCharsets.UTF_8),
                signed.signature());

        assertThat(signer().verify(tampered)).isFalse();
    }

    @Test
    default void algorithmMismatchesFail() {
        assertThat(mismatchedAlgorithm()).isNotEqualTo(signingKey().algorithm());
        final SignedDocument signed = signer().sign(signingKey(), contractDocument());
        final SignedDocument relabeled = new SignedDocument(
                mismatchedAlgorithm().joseAlg(),
                signed.keyId(),
                signed.publicKey(),
                signed.payload(),
                signed.signature());

        assertThat(signer().verify(relabeled)).isFalse();
    }

    @Test
    default void anchoredVerifyAcceptsTheTrustedKey() {
        final SignedDocument signed = signer().sign(signingKey(), contractDocument());
        final TrustAnchor anchor = TrustAnchor.pinnedKeys(Map.of(signed.keyId(), signed.publicKey()));

        assertThat(signer().verify(signed, anchor)).isTrue();
    }

    @Test
    default void anchoredVerifyFailsClosedOnASubstitutedKey() {
        // The key-substitution forgery the anchor exists to stop: same key id, different key
        // material. The anchor must reject before any signature computation.
        final SignedDocument signed = signer().sign(signingKey(), contractDocument());
        final byte[] substituted = signed.publicKey();
        substituted[0] ^= 0x01;
        final TrustAnchor anchor = TrustAnchor.pinnedKeys(Map.of(signed.keyId(), substituted));

        assertThat(signer().verify(signed, anchor)).isFalse();
    }

    @Test
    default void anchoredVerifyFailsClosedOnAnUnknownKeyId() {
        final SignedDocument signed = signer().sign(signingKey(), contractDocument());
        final TrustAnchor anchor =
                TrustAnchor.pinnedKeys(Map.of(signed.keyId() + "-rotated-away", signed.publicKey()));

        assertThat(signer().verify(signed, anchor)).isFalse();
    }
}
