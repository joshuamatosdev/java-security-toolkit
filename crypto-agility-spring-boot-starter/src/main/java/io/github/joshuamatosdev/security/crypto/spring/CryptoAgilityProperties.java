package io.github.joshuamatosdev.security.crypto.spring;

import io.github.joshuamatosdev.security.crypto.api.SignatureAlgorithm;
import io.github.joshuamatosdev.security.shared.RequiredText;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for the crypto-agility Spring Boot starter.
 *
 * <p>The starter gate ({@code bulwark.crypto.enabled}), the provider toggles
 * ({@code bulwark.crypto.providers.jca.*.enabled}), and the local ephemeral key opt-in
 * ({@code bulwark.crypto.local-ephemeral-keys.enabled}) are read only by
 * {@code @ConditionalOnProperty} conditions in {@link CryptoAgilityAutoConfiguration}, so this
 * record deliberately does not bind them — it binds exactly the values the wiring consumes, and
 * the starter's configuration metadata documents every key for IDE completion.
 *
 * @param defaultAlgorithm algorithm used when a caller does not name one; defaults to Ed25519
 * @param defaultKeyId key identifier handed to the key-handle resolver for default signing;
 *     defaults to the local demo identifier {@code local-ed25519-1}
 */
@ConfigurationProperties(prefix = "bulwark.crypto")
public record CryptoAgilityProperties(SignatureAlgorithm defaultAlgorithm, String defaultKeyId) {

    static final SignatureAlgorithm DEFAULT_ALGORITHM = SignatureAlgorithm.ED25519;
    static final String DEFAULT_KEY_ID = "local-ed25519-1";

    /** Applies defaults and rejects malformed key identifiers before any bean consumes them. */
    public CryptoAgilityProperties {
        defaultAlgorithm = defaultAlgorithm == null ? DEFAULT_ALGORITHM : defaultAlgorithm;
        defaultKeyId = defaultKeyId == null ? DEFAULT_KEY_ID : defaultKeyId;
        final String boundKeyId = defaultKeyId;
        RequiredText.violation(boundKeyId).ifPresent(violation -> {
            throw new IllegalArgumentException("bulwark.crypto.default-key-id " + violation);
        });
    }
}
