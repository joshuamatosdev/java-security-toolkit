package io.github.joshuamatosdev.security.edge.testkit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.edge.config.EdgePerimeterProperties;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Reusable contract tests for edge perimeter deployment-policy properties. */
public interface EdgePerimeterPropertiesContract {

    @Test
    default void hardenedDefaultsAreApplied() {
        final EdgePerimeterProperties properties = new EdgePerimeterProperties(null, null, null, null, null);

        assertThat(properties.cookie().secure()).isTrue();
        assertThat(properties.hsts().unconditional()).isTrue();
        assertThat(properties.identity().issuerUri()).isEqualTo(EdgePerimeterProperties.DEFAULT_ISSUER_URI);
        assertThat(properties.serviceJwt().audiences())
                .containsExactly(EdgePerimeterProperties.DEFAULT_SERVICE_AUDIENCE);
    }

    @Test
    default void nonLoopbackHttpIssuerIsRejected() {
        assertThatThrownBy(() -> new EdgePerimeterProperties(
                        null,
                        null,
                        null,
                        new EdgePerimeterProperties.Identity("http://idp.example.test"),
                        new EdgePerimeterProperties.ServiceJwt(List.of("edge-service-api"))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must use HTTPS except for loopback");
    }
}
