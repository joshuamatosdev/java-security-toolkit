package io.github.joshuamatosdev.security.tenant.datasource.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.tenant.TenantIds;
import io.github.joshuamatosdev.security.tenant.testfixtures.TenantTestConstants;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

/**
 * Tenant Claim Signer test coverage.
 *
 * <p>Why this is important to test: every borrowed connection must carry a valid tenant claim, or
 * database policies cannot reliably isolate tenant data.
 */
class TenantClaimSignerTest {

    private static final Duration TTL = Duration.ofMinutes(30);
    private static final Instant FIXED_NOW = Instant.parse("2026-06-02T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);

    @Test
    void signsVersionedClaimWithExpiry() {
        final TenantClaimSigner signer = new TenantClaimSigner(TenantTestConstants.CLAIM_SECRET, TTL, CLOCK);

        final String claim = signer.sign(TenantIds.ACME.value());

        final long expectedExp = FIXED_NOW.plus(TTL).getEpochSecond();
        assertThat(claim)
                .matches("v2:" + TenantIds.ACME.value() + ":" + expectedExp + ":[0-9a-f]{64}")
                .isEqualTo(signer.sign(TenantIds.ACME.value()));
    }

    @Test
    void expiryTracksTheClockAndTtl() {
        final Clock later = Clock.fixed(FIXED_NOW.plus(Duration.ofMinutes(5)), ZoneOffset.UTC);

        final long earlyExp = expOf(new TenantClaimSigner(TenantTestConstants.CLAIM_SECRET, TTL, CLOCK)
                .sign(TenantIds.ACME.value()));
        final long laterExp = expOf(new TenantClaimSigner(TenantTestConstants.CLAIM_SECRET, TTL, later)
                .sign(TenantIds.ACME.value()));

        assertThat(earlyExp).isEqualTo(FIXED_NOW.plus(TTL).getEpochSecond());
        assertThat(laterExp - earlyExp).isEqualTo(Duration.ofMinutes(5).toSeconds());
    }

    @Test
    void fractionalIssueTimePreservesTheFullConfiguredTtl() {
        final Instant fractionalNow = Instant.parse("2026-06-02T00:00:00.750Z");
        final Duration oneSecond = Duration.ofSeconds(1);
        final TenantClaimSigner signer = new TenantClaimSigner(
                TenantTestConstants.CLAIM_SECRET,
                oneSecond,
                Clock.fixed(fractionalNow, ZoneOffset.UTC));

        final long exp = expOf(signer.sign(TenantIds.ACME.value()));

        assertThat(exp).isEqualTo(fractionalNow.plus(oneSecond).getEpochSecond() + 1);
    }

    @Test
    void tenantAndSecretBothAffectTheSignature() {
        final TenantClaimSigner signer = new TenantClaimSigner(TenantTestConstants.CLAIM_SECRET, TTL, CLOCK);
        final TenantClaimSigner otherSecret =
                new TenantClaimSigner("another-local-tenant-claim-secret-with-32-bytes", TTL, CLOCK);

        assertThat(signer.sign(TenantIds.ACME.value())).isNotEqualTo(signer.sign(TenantIds.GLOBEX.value()));
        assertThat(signer.sign(TenantIds.ACME.value())).isNotEqualTo(otherSecret.sign(TenantIds.ACME.value()));
    }

    @Test
    void rejectsMissingWeakSecretsOrNonPositiveTtl() {
        assertThatThrownBy(() -> new TenantClaimSigner(" ", TTL, CLOCK))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must be populated");
        assertThatThrownBy(() -> new TenantClaimSigner("too-short", TTL, CLOCK))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at least 32 bytes");
        assertThatThrownBy(() -> new TenantClaimSigner(TenantTestConstants.CLAIM_SECRET, Duration.ZERO, CLOCK))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("TTL must be positive");
    }

    @Test
    void rejectsSecretsWithLeadingOrTrailingWhitespace() {
        assertThatThrownBy(() -> new TenantClaimSigner(TenantTestConstants.CLAIM_SECRET + " ", TTL, CLOCK))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("tenant claim secret must not include leading or trailing whitespace");
    }

    @Test
    void rejectsSecretsWithControlCharacters() {
        assertThatThrownBy(() -> new TenantClaimSigner(TenantTestConstants.CLAIM_SECRET + "\nforged", TTL, CLOCK))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("tenant claim secret must not contain control characters");
    }

    @Test
    void rejectsSubSecondTtlBecauseClaimsAreSerializedInEpochSeconds() {
        assertThatThrownBy(() -> new TenantClaimSigner(
                        TenantTestConstants.CLAIM_SECRET, Duration.ofMillis(1), CLOCK))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at least 1 second");
    }

    private static long expOf(final String claim) {
        return Long.parseLong(claim.split(":")[2]);
    }
}
