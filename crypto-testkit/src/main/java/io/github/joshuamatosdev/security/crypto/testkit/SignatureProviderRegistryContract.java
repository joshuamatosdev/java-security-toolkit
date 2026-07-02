package io.github.joshuamatosdev.security.crypto.testkit;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.crypto.api.SignatureProvider;
import io.github.joshuamatosdev.security.crypto.api.SignatureProviderRegistry;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Reusable registry wiring contract tests. */
public interface SignatureProviderRegistryContract {

    /** Two providers that intentionally report the same algorithm. */
    List<SignatureProvider> duplicateProviders();

    @Test
    default void duplicateProvidersFail() {
        assertThatThrownBy(() -> new SignatureProviderRegistry(duplicateProviders()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Duplicate provider");
    }
}
