package io.github.joshuamatosdev.security.authz.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.authz.decision.Allow;
import io.github.joshuamatosdev.security.authz.decision.DenialReason;
import io.github.joshuamatosdev.security.authz.decision.Deny;
import io.github.joshuamatosdev.security.authz.decision.GrantBasis;
import io.github.joshuamatosdev.security.authz.policy.Action;
import io.github.joshuamatosdev.security.authz.principal.PrincipalType;
import io.github.joshuamatosdev.security.shared.ResourceId;
import io.github.joshuamatosdev.security.shared.TenantId;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AuthorizationAuditRecordTest {

    private static final Instant AT = Instant.parse("2026-06-02T12:00:00Z");
    private static final UUID CORRELATION = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    private static final TenantId TENANT =
            new TenantId(UUID.fromString("11111111-1111-1111-1111-111111111111"));
    private static final ResourceId RESOURCE =
            new ResourceId(UUID.fromString("33333333-3333-3333-3333-333333333333"));

    @Test
    void outcomeIsExactlyAnAllowOrDenyWithItsRationale() {
        var allow = record(TENANT, new Allow(GrantBasis.WIDE_SCOPE_ADMIN), "alice");
        var deny = record(null, new Deny(DenialReason.NO_MATCHING_RULE), "alice");

        assertThat(allow.outcome()).isEqualTo(new Allow(GrantBasis.WIDE_SCOPE_ADMIN));
        assertThat(deny.outcome()).isEqualTo(new Deny(DenialReason.NO_MATCHING_RULE));
    }

    @Test
    void allowedRecordRequiresTrustedTenantContext() {
        assertThatThrownBy(() -> record(null, new Allow(GrantBasis.RESOURCE_OWNER), "alice"))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("tenantId");
    }

    @Test
    void deniedBoundaryRecordMayOmitTrustedTenantContext() {
        assertThatCode(() -> record(null, new Deny(DenialReason.TENANT_MISMATCH), "alice"))
                .doesNotThrowAnyException();
    }

    @Test
    void outcomeIsRequired() {
        assertThatThrownBy(() -> record(TENANT, null, "alice"))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("outcome");
    }

    @Test
    void principalKeyUsesRequiredTextPolicy() {
        assertThatThrownBy(() -> record(TENANT, new Allow(GrantBasis.RESOURCE_OWNER), " alice"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("principalKey must not include leading or trailing whitespace");
        assertThatThrownBy(() -> record(TENANT, new Allow(GrantBasis.RESOURCE_OWNER), "alice\nforged"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("principalKey must not contain control characters");
    }

    private static AuthorizationAuditRecord record(
            final TenantId tenantId,
            final io.github.joshuamatosdev.security.authz.decision.Decision outcome,
            final String principalKey) {
        return new AuthorizationAuditRecord(
                AT,
                CORRELATION,
                PrincipalType.USER,
                principalKey,
                tenantId,
                RESOURCE,
                null,
                Action.READ,
                outcome);
    }
}
