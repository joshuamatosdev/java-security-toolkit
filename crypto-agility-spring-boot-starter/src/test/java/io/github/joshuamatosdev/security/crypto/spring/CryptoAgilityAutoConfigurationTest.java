package io.github.joshuamatosdev.security.crypto.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.crypto.api.DocumentSigner;
import io.github.joshuamatosdev.security.crypto.api.KeyHandleResolver;
import io.github.joshuamatosdev.security.crypto.api.SignatureAlgorithm;
import io.github.joshuamatosdev.security.crypto.api.SignatureProvider;
import io.github.joshuamatosdev.security.crypto.api.SignatureProviderRegistry;
import io.github.joshuamatosdev.security.crypto.api.SignedDocument;
import io.github.joshuamatosdev.security.crypto.jca.JcaSignatureProviders;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

class CryptoAgilityAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(CryptoAgilityAutoConfiguration.class));

    @Test
    void defaultContextRegistersEd25519DocumentSignerWithoutLocalSigningCustody() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(DocumentSigner.class);
            assertThat(context).doesNotHaveBean(KeyHandleResolver.class);
            final SignatureProviderRegistry registry = context.getBean(SignatureProviderRegistry.class);
            assertThat(registry.hasProvider(SignatureAlgorithm.ED25519)).isTrue();
            assertThat(registry.hasProvider(SignatureAlgorithm.ECDSA_P256)).isFalse();
            assertThat(registry.hasProvider(SignatureAlgorithm.ML_DSA_44)).isFalse();

            final DocumentSigner signer = context.getBean(DocumentSigner.class);
            assertThatThrownBy(() -> signer.sign("payload".getBytes(StandardCharsets.UTF_8)))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Default signing requires");
        });
    }

    @Test
    void applicationKeyHandleResolverEnablesDefaultSigning() {
        contextRunner
                .withUserConfiguration(ApplicationKeyHandleResolverConfiguration.class)
                .run(context -> {
                    assertThat(context).hasSingleBean(KeyHandleResolver.class);

                    final DocumentSigner signer = context.getBean(DocumentSigner.class);
                    final SignedDocument signed = signer.sign("payload".getBytes(StandardCharsets.UTF_8));

                    assertThat(signed.alg()).isEqualTo("EdDSA");
                    assertThat(signer.verify(signed)).isTrue();
                });
    }

    @Test
    void localEphemeralKeysAreExplicitOptIn() {
        contextRunner
                .withPropertyValues("bulwark.crypto.local-ephemeral-keys.enabled=true")
                .run(context -> {
                    assertThat(context).hasSingleBean(KeyHandleResolver.class);

                    final DocumentSigner signer = context.getBean(DocumentSigner.class);
                    final SignedDocument signed = signer.sign("payload".getBytes(StandardCharsets.UTF_8));

                    assertThat(signed.alg()).isEqualTo("EdDSA");
                    assertThat(signer.verify(signed)).isTrue();
                });
    }

    @Test
    void ecdsaP256ProviderIsOptIn() {
        contextRunner
                .withPropertyValues("bulwark.crypto.providers.jca.ecdsa-p256.enabled=true")
                .run(context -> {
                    final SignatureProviderRegistry registry = context.getBean(SignatureProviderRegistry.class);
                    assertThat(registry.hasProvider(SignatureAlgorithm.ED25519)).isTrue();
                    assertThat(registry.hasProvider(SignatureAlgorithm.ECDSA_P256)).isTrue();
                    assertThat(registry.hasProvider(SignatureAlgorithm.ML_DSA_44)).isFalse();
                });
    }

    @Test
    void missingDefaultProviderFailsStartup() {
        contextRunner
                .withPropertyValues("bulwark.crypto.providers.jca.ed25519.enabled=false")
                .run(context -> assertThat(context.getStartupFailure())
                        .hasMessageContaining("No SignatureProvider registered for default algorithm ED25519"));
    }

    @Test
    void blankDefaultKeyIdFailsStartup() {
        contextRunner
                .withPropertyValues("bulwark.crypto.default-key-id= ")
                .run(context -> assertThat(context.getStartupFailure())
                        .hasMessageContaining("bulwark.crypto.default-key-id must not be blank"));
    }

    @Test
    void keyIdStrategyRejectsMalformedConfiguredDefaultKeyIds() {
        final CryptoAgilityAutoConfiguration configuration = new CryptoAgilityAutoConfiguration();

        assertThatThrownBy(() -> configuration.keyIdStrategy(propertiesWithDefaultKeyId(" local-ed25519-1")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("bulwark.crypto.default-key-id must not include leading or trailing whitespace");
        assertThatThrownBy(() -> configuration.keyIdStrategy(propertiesWithDefaultKeyId("local-ed25519-1 ")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("bulwark.crypto.default-key-id must not include leading or trailing whitespace");
        assertThatThrownBy(() -> configuration.keyIdStrategy(propertiesWithDefaultKeyId("local-ed25519-1\u0000")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("bulwark.crypto.default-key-id must not contain control characters");
    }

    @Test
    void duplicateProvidersFailStartup() {
        contextRunner
                .withUserConfiguration(DuplicateProviderConfiguration.class)
                .run(context -> assertThat(context.getStartupFailure())
                        .hasMessageContaining("Duplicate provider for algorithm ED25519"));
    }

    @Configuration(proxyBeanMethods = false)
    static class DuplicateProviderConfiguration {
        @Bean
        SignatureProvider duplicateEd25519SignatureProvider() {
            return JcaSignatureProviders.ed25519();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class ApplicationKeyHandleResolverConfiguration {
        @Bean
        KeyHandleResolver applicationKeyHandleResolver(final SignatureProviderRegistry registry) {
            return (algorithm, keyId) -> registry.resolve(algorithm).generateKey(keyId);
        }
    }

    private static CryptoAgilityProperties propertiesWithDefaultKeyId(final String defaultKeyId) {
        final CryptoAgilityProperties properties = new CryptoAgilityProperties();
        properties.setDefaultKeyId(defaultKeyId);
        return properties;
    }
}
