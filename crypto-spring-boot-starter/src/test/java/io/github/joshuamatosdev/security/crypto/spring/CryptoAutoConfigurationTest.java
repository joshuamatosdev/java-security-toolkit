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

class CryptoAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(CryptoAutoConfiguration.class));

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
                .withPropertyValues("crypto.local-ephemeral-keys.enabled=true")
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
                .withPropertyValues("crypto.providers.jca.ecdsa-p256.enabled=true")
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
                .withPropertyValues("crypto.providers.jca.ed25519.enabled=false")
                .run(context -> assertThat(context.getStartupFailure())
                        .hasMessageContaining("No SignatureProvider registered for default algorithm ED25519"));
    }

    @Test
    void blankDefaultKeyIdFailsStartup() {
        contextRunner
                .withPropertyValues("crypto.default-key-id= ")
                .run(context -> assertThat(context.getStartupFailure())
                        .rootCause()
                        .hasMessage("crypto.default-key-id must not be blank"));
    }

    @Test
    void malformedDefaultKeyIdsAreRejectedAtBind() {
        assertThatThrownBy(() -> new CryptoProperties(null, " local-ed25519-1"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("crypto.default-key-id must not include leading or trailing whitespace");
        assertThatThrownBy(() -> new CryptoProperties(null, "local-ed25519-1 "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("crypto.default-key-id must not include leading or trailing whitespace");
        assertThatThrownBy(() -> new CryptoProperties(null, "local-ed25519-1" + (char) 0x00))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("crypto.default-key-id must not contain control characters");
    }

    @Test
    void unsetPropertiesFallBackToEd25519Defaults() {
        final CryptoProperties properties = new CryptoProperties(null, null);

        assertThat(properties.defaultAlgorithm()).isEqualTo(SignatureAlgorithm.ED25519);
        assertThat(properties.defaultKeyId()).isEqualTo("local-ed25519-1");
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
}
