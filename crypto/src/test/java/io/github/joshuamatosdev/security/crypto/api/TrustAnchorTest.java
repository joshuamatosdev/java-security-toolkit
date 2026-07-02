package io.github.joshuamatosdev.security.crypto.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Pins the pinned-key trust anchor's contract: exact-match trust, defensive copies, and validated
 * construction.
 *
 * <p>Why this is important to test: the anchor is the authenticity boundary — if it trusted a key
 * it was never pinned with, or could be mutated after construction, the anchored verify would
 * inherit the exact forgery gap it exists to close.
 */
class TrustAnchorTest {

    private static final byte[] KEY = "encoded-public-key".getBytes(StandardCharsets.UTF_8);

    @Test
    void trustsExactlyThePinnedEntries() {
        final TrustAnchor anchor = TrustAnchor.pinnedKeys(Map.of("k1", KEY));

        assertThat(anchor.trusts("k1", KEY.clone())).isTrue();
        assertThat(anchor.trusts("k2", KEY.clone())).isFalse();
        assertThat(anchor.trusts("k1", "different-key".getBytes(StandardCharsets.UTF_8))).isFalse();
        assertThat(anchor.trusts(null, KEY.clone())).isFalse();
        assertThat(anchor.trusts("k1", null)).isFalse();
    }

    @Test
    void pinnedMaterialIsDefensivelyCopied() {
        final byte[] mutated = KEY.clone();
        final Map<String, byte[]> entries = new HashMap<>();
        entries.put("k1", mutated);
        final TrustAnchor anchor = TrustAnchor.pinnedKeys(entries);

        mutated[0] ^= 0x01;

        assertThat(anchor.trusts("k1", KEY.clone()))
                .as("mutating the caller's array after construction must not move the anchor")
                .isTrue();
        assertThat(anchor.trusts("k1", mutated)).isFalse();
    }

    @Test
    void constructionRejectsBlankKeyIdsAndEmptyKeyMaterial() {
        assertThatThrownBy(() -> TrustAnchor.pinnedKeys(Map.of(" ", KEY)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("keyId must not be blank");
        assertThatThrownBy(() -> TrustAnchor.pinnedKeys(Map.of("k1", new byte[0])))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("publicKey must not be empty for key id k1");
        assertThatThrownBy(() -> TrustAnchor.pinnedKeys(null))
                .isInstanceOf(NullPointerException.class);
    }
}
