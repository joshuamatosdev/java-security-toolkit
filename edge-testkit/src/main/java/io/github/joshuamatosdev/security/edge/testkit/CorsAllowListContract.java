package io.github.joshuamatosdev.security.edge.testkit;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.edge.config.CorsAllowListConfig;
import io.github.joshuamatosdev.security.edge.config.EdgeProperties;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Reusable contract tests for the credentialed CORS allow-list startup guard. Implement this in an
 * adopting application's test suite to prove the guard still refuses the configurations that would
 * let untrusted or network-tamperable browser contexts script authenticated requests.
 */
public interface CorsAllowListContract {

    private static EdgeProperties withOrigins(final String... origins) {
        return new EdgeProperties(new EdgeProperties.Cors(List.of(origins)), null, null);
    }

    @Test
    default void credentialedCorsRejectsTheWildcardOrigin() {
        assertThatThrownBy(() -> new CorsAllowListConfig().corsConfigurationSource(withOrigins("*")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Credentialed CORS cannot use '*'");
    }

    @Test
    default void credentialedCorsRejectsTheOpaqueNullOrigin() {
        assertThatThrownBy(() -> new CorsAllowListConfig().corsConfigurationSource(withOrigins("null")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("opaque 'null' origin");
    }

    @Test
    default void credentialedCorsRejectsNonLoopbackHttpOrigins() {
        assertThatThrownBy(() -> new CorsAllowListConfig()
                        .corsConfigurationSource(withOrigins("http://app.acme.example")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("must use HTTPS except for loopback");
    }

    @Test
    default void credentialedCorsAcceptsHttpsOriginsAndLoopbackDevelopmentOrigins() {
        assertThatCode(() -> new CorsAllowListConfig()
                        .corsConfigurationSource(
                                withOrigins("https://app.acme.example", "http://localhost:5173")))
                .doesNotThrowAnyException();
    }
}
