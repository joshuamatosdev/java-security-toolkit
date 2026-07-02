package io.github.joshuamatosdev.security.crypto.api;

import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Decides whether a public key is the one the deployment trusts for a key id.
 *
 * <p>{@link DocumentSigner#verify(SignedDocument)} proves payload integrity under the public key
 * <em>embedded in the document</em> — an attacker who re-signs a tampered payload with their own
 * key and embeds that key produces a document that still verifies. Authenticity requires the
 * verifier to hold its own opinion of which key is allowed to speak for a key id; this seam is
 * where that opinion lives. Production deployments can back it with key custody (KMS public-key
 * lookup, a distributed key directory); {@link #pinnedKeys(Map)} is the static pinned-set
 * implementation.
 */
@FunctionalInterface
public interface TrustAnchor {

    /** True when {@code publicKey} is the trusted key material for {@code keyId}. */
    boolean trusts(String keyId, byte[] publicKey);

    /**
     * A pinned key set: exactly the supplied {@code keyId → encoded public key} entries are
     * trusted, nothing else. Key material is defensively copied, and the comparison is
     * constant-time so the anchor itself leaks nothing about how close an untrusted key is to a
     * pinned one.
     */
    static TrustAnchor pinnedKeys(final Map<String, byte[]> publicKeysByKeyId) {
        Objects.requireNonNull(publicKeysByKeyId, "publicKeysByKeyId must not be null");
        final Map<String, byte[]> pinned = new HashMap<>();
        for (final Map.Entry<String, byte[]> entry : publicKeysByKeyId.entrySet()) {
            final String keyId = Objects.requireNonNull(entry.getKey(), "keyId must not be null");
            if (keyId.isBlank()) {
                throw new IllegalArgumentException("keyId must not be blank");
            }
            final byte[] publicKey =
                    Objects.requireNonNull(entry.getValue(), "publicKey must not be null for key id " + keyId);
            if (publicKey.length == 0) {
                throw new IllegalArgumentException("publicKey must not be empty for key id " + keyId);
            }
            pinned.put(keyId, publicKey.clone());
        }
        return (keyId, publicKey) -> {
            if (keyId == null || publicKey == null) {
                return false;
            }
            final byte[] trusted = pinned.get(keyId);
            return trusted != null && MessageDigest.isEqual(trusted, publicKey);
        };
    }
}
