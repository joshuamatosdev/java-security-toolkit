package io.github.joshuamatosdev.security.crypto.spring;

import io.github.joshuamatosdev.security.crypto.api.DocumentSigner;
import io.github.joshuamatosdev.security.crypto.api.KeyHandle;
import io.github.joshuamatosdev.security.crypto.api.KeyHandleResolver;
import io.github.joshuamatosdev.security.crypto.api.KeyIdStrategy;
import io.github.joshuamatosdev.security.crypto.api.SignatureAlgorithm;
import io.github.joshuamatosdev.security.crypto.api.SignatureAuditSink;
import io.github.joshuamatosdev.security.crypto.api.SignatureEnvelopeCodec;
import io.github.joshuamatosdev.security.crypto.api.SignatureProvider;
import io.github.joshuamatosdev.security.crypto.api.SignatureProviderRegistry;
import io.github.joshuamatosdev.security.crypto.internal.DefaultSignatureEnvelopeCodec;
import io.github.joshuamatosdev.security.crypto.jca.JcaSignatureProviders;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/** Spring Boot auto-configuration for crypto-agility consumers. */
@AutoConfiguration
@ConditionalOnClass(DocumentSigner.class)
@ConditionalOnProperty(prefix = "glyptodon.crypto", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(CryptoAgilityProperties.class)
public class CryptoAgilityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(name = "ed25519SignatureProvider")
    @ConditionalOnProperty(
            prefix = "glyptodon.crypto.providers.jca.ed25519",
            name = "enabled",
            havingValue = "true",
            matchIfMissing = true)
    SignatureProvider ed25519SignatureProvider() {
        return JcaSignatureProviders.ed25519();
    }

    @Bean
    @ConditionalOnMissingBean(name = "ecdsaP256SignatureProvider")
    @ConditionalOnProperty(
            prefix = "glyptodon.crypto.providers.jca.ecdsa-p256",
            name = "enabled",
            havingValue = "true")
    SignatureProvider ecdsaP256SignatureProvider() {
        return JcaSignatureProviders.ecdsaP256();
    }

    @Bean
    @ConditionalOnMissingBean(name = "mlDsa44PlaceholderSignatureProvider")
    @ConditionalOnProperty(
            prefix = "glyptodon.crypto.providers.jca.ml-dsa-44-placeholder",
            name = "enabled",
            havingValue = "true")
    SignatureProvider mlDsa44PlaceholderSignatureProvider() {
        return JcaSignatureProviders.postQuantumPlaceholder();
    }

    @Bean
    @ConditionalOnMissingBean
    SignatureProviderRegistry signatureProviderRegistry(final List<SignatureProvider> providers) {
        return new SignatureProviderRegistry(providers);
    }

    @Bean
    @ConditionalOnMissingBean
    SignatureEnvelopeCodec signatureEnvelopeCodec() {
        return new DefaultSignatureEnvelopeCodec();
    }

    @Bean
    @ConditionalOnMissingBean
    SignatureAuditSink signatureAuditSink() {
        return SignatureAuditSink.noop();
    }

    @Bean
    @ConditionalOnMissingBean
    KeyIdStrategy keyIdStrategy(final CryptoAgilityProperties properties) {
        return algorithm -> requireNonBlank(properties.getDefaultKeyId(), "glyptodon.crypto.default-key-id");
    }

    @Bean
    @ConditionalOnMissingBean
    KeyHandleResolver keyHandleResolver(final SignatureProviderRegistry registry) {
        final Map<String, KeyHandle> keys = new ConcurrentHashMap<>();
        return (algorithm, keyId) -> keys.computeIfAbsent(
                algorithm.name() + ":" + keyId,
                ignored -> registry.resolve(algorithm).generateKey(keyId));
    }

    @Bean
    @ConditionalOnMissingBean
    DocumentSigner documentSigner(
            final SignatureProviderRegistry registry,
            final CryptoAgilityProperties properties,
            final KeyHandleResolver keyHandleResolver,
            final KeyIdStrategy keyIdStrategy,
            final SignatureEnvelopeCodec envelopeCodec,
            final SignatureAuditSink auditSink) {
        final SignatureAlgorithm defaultAlgorithm =
                Objects.requireNonNull(properties.getDefaultAlgorithm(), "glyptodon.crypto.default-algorithm");
        if (!registry.hasProvider(defaultAlgorithm)) {
            throw new IllegalStateException(
                    "No SignatureProvider registered for default algorithm " + defaultAlgorithm);
        }
        return new DocumentSigner(
                registry,
                defaultAlgorithm,
                keyHandleResolver,
                keyIdStrategy,
                envelopeCodec,
                auditSink);
    }

    private static String requireNonBlank(final String value, final String propertyName) {
        Objects.requireNonNull(value, propertyName + " must not be null");
        if (value.isBlank()) {
            throw new IllegalStateException(propertyName + " must not be blank");
        }
        return value;
    }
}
