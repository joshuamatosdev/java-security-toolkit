package io.github.joshuamatosdev.security.crypto.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.crypto.jca.JcaSignatureProviders;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

class SignatureProviderRegistryTest {

    @Test
    void resolveReturnsProviderForAlgorithmAndExposesImmutableView() {
        final SignatureProviderRegistry registry = new SignatureProviderRegistry(
                List.of(JcaSignatureProviders.ed25519(), JcaSignatureProviders.ecdsaP256()));

        assertThat(registry.resolve(SignatureAlgorithm.ECDSA_P256).algorithm())
                .isEqualTo(SignatureAlgorithm.ECDSA_P256);
        assertThat(registry.hasProvider(SignatureAlgorithm.ED25519)).isTrue();
        assertThatThrownBy(() -> registry.providersByAlgorithm().clear())
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void constructionRejectsDuplicateAndNullProviderConfiguration() {
        assertThatThrownBy(() -> new SignatureProviderRegistry(
                        List.of(JcaSignatureProviders.ed25519(), JcaSignatureProviders.ed25519())))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Duplicate provider");

        assertThatThrownBy(() -> new SignatureProviderRegistry(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("providers must not be null");
        assertThatThrownBy(() -> new SignatureProviderRegistry(Collections.singletonList(null)))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("provider must not be null");
    }
}
