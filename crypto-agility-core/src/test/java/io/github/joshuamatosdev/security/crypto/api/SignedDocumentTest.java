package io.github.joshuamatosdev.security.crypto.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class SignedDocumentTest {

    private static final byte[] PAYLOAD = "payload".getBytes(StandardCharsets.UTF_8);

    @Test
    void equalityUsesByteContentRatherThanArrayIdentity() {
        final SignedDocument first =
                new SignedDocument("EdDSA", "k1", new byte[] {1}, PAYLOAD, new byte[] {2});
        final SignedDocument second =
                new SignedDocument("EdDSA", "k1", new byte[] {1}, PAYLOAD.clone(), new byte[] {2});

        assertThat(second).isEqualTo(first);
        assertThat(second.hashCode()).isEqualTo(first.hashCode());
    }

    @Test
    void arraysAreDefensivelyCopied() {
        final byte[] publicKey = {1};
        final byte[] signature = {2};
        final SignedDocument document = new SignedDocument("EdDSA", "k1", publicKey, PAYLOAD, signature);
        publicKey[0] = 9;
        signature[0] = 9;

        assertThat(document.publicKey()).containsExactly((byte) 1);
        assertThat(document.signature()).containsExactly((byte) 2);
        document.publicKey()[0] = 8;
        assertThat(document.publicKey()).containsExactly((byte) 1);
    }

    @Test
    void rejectsBlankPaddedOrControlMetadata() {
        assertThatThrownBy(() -> new SignedDocument(" ", "k1", new byte[] {1}, PAYLOAD, new byte[] {2}))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("alg must not be blank");
        assertThatThrownBy(() -> new SignedDocument(" EdDSA", "k1", new byte[] {1}, PAYLOAD, new byte[] {2}))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("alg must not contain leading or trailing whitespace");
        assertThatThrownBy(() -> new SignedDocument("EdDSA\nforged", "k1", new byte[] {1}, PAYLOAD, new byte[] {2}))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("alg must not contain control characters");
    }
}
