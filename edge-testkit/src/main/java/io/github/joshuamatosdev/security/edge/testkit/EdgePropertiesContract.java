package io.github.joshuamatosdev.security.edge.testkit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.edge.config.EdgeProperties;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Reusable contract tests for edge perimeter deployment-policy properties. */
public interface EdgePropertiesContract {

    @Test
    default void hardenedDefaultsAreApplied() {
        final EdgeProperties properties = new EdgeProperties(null, null, null, null, null);

        assertThat(properties.cookie().secure()).isTrue();
        assertThat(properties.hsts().unconditional()).isTrue();
        assertThat(properties.identity().issuerUri()).isEqualTo(EdgeProperties.DEFAULT_ISSUER_URI);
        assertThat(properties.serviceJwt().audiences())
                .containsExactly(EdgeProperties.DEFAULT_SERVICE_AUDIENCE);
    }

    @Test
    default void nonLoopbackHttpIssuerIsRejected() {
        assertThatThrownBy(() -> new EdgeProperties(
                        null,
                        null,
                        null,
                        new EdgeProperties.Identity("http://idp.example.test"),
                        new EdgeProperties.ServiceJwt(List.of("edge-service-api"))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must use HTTPS except for loopback");
    }
}
