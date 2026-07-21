package io.github.joshuamatosdev.security.tenant.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.tenant.testfixtures.TenantTestConstants;
import java.time.Duration;
import org.junit.jupiter.api.Test;

/**
 * Tenant Binding Properties test coverage.
 *
 * <p>Why this is important to test: configuration mistakes can route tenant data through the wrong
 * placement mode or unsafe credentials before SQL ever runs.
 */
class TenantBindingPropertiesTest {

    @Test
    void claimSecretRejectsLeadingOrTrailingWhitespace() {
        assertThatThrownBy(() -> new TenantBindingProperties(
                        TenantTestConstants.CLAIM_SECRET + " ",
                        TenantTestConstants.DEV_PASSWORD)
                .requireClaimSecret())
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("tenant.binding.claim-secret must not include leading or trailing whitespace");
    }

    @Test
    void claimSecretRejectsControlCharacters() {
        assertThatThrownBy(() -> new TenantBindingProperties(
                        TenantTestConstants.CLAIM_SECRET.substring(0, 10)
                                + "\n"
                                + TenantTestConstants.CLAIM_SECRET.substring(10),
                        TenantTestConstants.DEV_PASSWORD)
                .requireClaimSecret())
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("tenant.binding.claim-secret must not contain control characters");
    }

    @Test
    void systemOpsPasswordRejectsLeadingOrTrailingWhitespaceWhenRequired() {
        assertThatThrownBy(() -> new TenantBindingProperties(
                        TenantTestConstants.CLAIM_SECRET,
                        TenantTestConstants.DEV_PASSWORD + " ")
                .requireSystemOpsPasswordForIdMode())
                .isInstanceOf(IllegalStateException.class)
                .hasMessage(
                        "tenant.binding.system-ops-password must not include leading or trailing whitespace");
    }

    @Test
    void populatedBindingValuesAreReturnedUnchanged() {
        final TenantBindingProperties properties = new TenantBindingProperties(
                TenantTestConstants.CLAIM_SECRET,
                TenantTestConstants.DEV_PASSWORD);

        assertThat(properties.requireClaimSecret()).isEqualTo(TenantTestConstants.CLAIM_SECRET);
        assertThat(properties.requireSystemOpsPasswordForIdMode()).isEqualTo(TenantTestConstants.DEV_PASSWORD);
        assertThat(properties.claimTtl()).isEqualTo(Duration.ofSeconds(120));
    }

    @Test
    void claimTtlCanCoverTheApplicationsLongestBorrow() {
        final TenantBindingProperties properties = new TenantBindingProperties(
                TenantTestConstants.CLAIM_SECRET,
                TenantTestConstants.DEV_PASSWORD,
                null,
                Duration.ofMinutes(15));

        assertThat(properties.claimTtl()).isEqualTo(Duration.ofMinutes(15));
    }

    @Test
    void claimTtlRejectsSubSecondValues() {
        assertThatThrownBy(() -> new TenantBindingProperties(
                        TenantTestConstants.CLAIM_SECRET,
                        TenantTestConstants.DEV_PASSWORD,
                        null,
                        Duration.ofMillis(999)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("tenant.binding.claim-ttl must be at least 1 second");
    }
}
