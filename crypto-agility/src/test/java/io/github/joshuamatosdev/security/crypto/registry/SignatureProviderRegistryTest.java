package io.github.joshuamatosdev.security.crypto.registry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.crypto.provider.SignatureProvider;
import io.github.joshuamatosdev.security.crypto.provider.SignatureProviders;
import java.util.List;
import org.junit.jupiter.api.Test;

class SignatureProviderRegistryTest {

    private final SignatureProviderRegistry registry =
            new SignatureProviderRegistry(
                    List.of(
                            SignatureProviders.ed25519(),
                            SignatureProviders.ecdsaP256(),
                            SignatureProviders.postQuantumPlaceholder()));

    @Test
    void resolveReturnsTheProviderForTheAlgorithm() {
        final SignatureProvider provider = registry.resolve(SignatureAlgorithm.ECDSA_P256);

        assertThat(provider.algorithm()).isEqualTo(SignatureAlgorithm.ECDSA_P256);
    }

    @Test
    void resolveFailsForAnAlgorithmWithNoProvider() {
        final SignatureProviderRegistry classicalOnly =
                new SignatureProviderRegistry(List.of(SignatureProviders.ed25519()));

        assertThatThrownBy(() -> classicalOnly.resolve(SignatureAlgorithm.ML_DSA_44))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ML_DSA_44");
    }

    @Test
    void constructionRejectsTwoProvidersForTheSameAlgorithm() {
        assertThatThrownBy(
                        () ->
                                new SignatureProviderRegistry(
                                        List.of(SignatureProviders.ed25519(), SignatureProviders.ed25519())))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Duplicate provider");
    }
}
