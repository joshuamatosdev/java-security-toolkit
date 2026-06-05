package io.github.joshuamatosdev.security.authz.audit;

import io.github.joshuamatosdev.security.authz.decision.DenialReason;
import io.github.joshuamatosdev.security.authz.decision.GrantBasis;
import io.github.joshuamatosdev.security.authz.policy.Action;
import io.github.joshuamatosdev.security.authz.principal.PrincipalType;
import io.github.joshuamatosdev.security.shared.ResourceId;
import io.github.joshuamatosdev.security.shared.TenantId;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Authorization Audit Record test coverage.
 *
 * <p>Why this is important to test: audit records are forensic evidence, and missing fields make
 * later authorization investigations incomplete.
 */
class AuthorizationAuditRecordTest {

    private static final Instant AT = Instant.parse("2026-06-02T12:00:00Z");
    private static final UUID CORRELATION = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    private static final TenantId TENANT =
        new TenantId(UUID.fromString("11111111-1111-1111-1111-111111111111"));
    private static final ResourceId RESOURCE =
        new ResourceId(UUID.fromString("33333333-3333-3333-3333-333333333333"));

    @Test
    void allowedRecordRequiresGrantBasis() {
        assertThatThrownBy(() -> record(true, null, null, false, TENANT))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("grantBasis");
    }

    @Test
    void allowedRecordRejectsDenialReason() {
        assertThatThrownBy(() ->
                record(true, GrantBasis.RESOURCE_OWNER, DenialReason.NO_MATCHING_RULE, false, TENANT))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("must not include denialReason");
    }

    @Test
    void allowedRecordRequiresTrustedTenantContext() {
        assertThatThrownBy(() -> record(true, GrantBasis.RESOURCE_OWNER, null, false, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("tenantId");
    }

    @Test
    void deniedRecordRequiresDenialReason() {
        assertThatThrownBy(() -> record(false, null, null, false, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("denialReason");
    }

    @Test
    void deniedRecordRejectsGrantBasis() {
        assertThatThrownBy(() ->
                record(false, GrantBasis.RESOURCE_OWNER, DenialReason.NO_MATCHING_RULE, false, TENANT))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("must not include grantBasis");
    }

    @Test
    void wideScopeMustMatchWideScopeAdminGrantBasis() {
        assertThatThrownBy(() -> record(true, GrantBasis.WIDE_SCOPE_ADMIN, null, false, TENANT))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("wideScope");
        assertThatThrownBy(() -> record(true, GrantBasis.RESOURCE_OWNER, null, true, TENANT))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("wideScope");
    }

    @Test
    void consistentAllowAndBoundaryDenyRecordsAreAccepted() {
        assertThatCode(() -> record(true, GrantBasis.WIDE_SCOPE_ADMIN, null, true, TENANT))
            .doesNotThrowAnyException();
        assertThatCode(() -> record(false, null, DenialReason.NO_MATCHING_RULE, false, null))
            .doesNotThrowAnyException();
    }

    @Test
    void principalKeyMustNotIncludeLeadingOrTrailingWhitespace() {
        assertThatThrownBy(() -> recordWithPrincipalKey(" alice"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("principalKey must not include leading or trailing whitespace");

        assertThatThrownBy(() -> recordWithPrincipalKey("alice "))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("principalKey must not include leading or trailing whitespace");
    }

    @Test
    void principalKeyMustNotContainControlCharacters() {
        assertThatThrownBy(() -> recordWithPrincipalKey("alice\nforged"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("principalKey must not contain control characters");
    }

    private static AuthorizationAuditRecord record(
        final boolean allowed,
        final GrantBasis grantBasis,
        final DenialReason denialReason,
        final boolean wideScope,
        final TenantId tenantId) {
        return new AuthorizationAuditRecord(
            AT,
            CORRELATION,
            PrincipalType.USER,
            "alice",
            tenantId,
            RESOURCE,
            null,
            Action.READ,
            allowed,
            grantBasis,
            denialReason,
            wideScope);
    }

    private static AuthorizationAuditRecord recordWithPrincipalKey(final String principalKey) {
        return new AuthorizationAuditRecord(
            AT,
            CORRELATION,
            PrincipalType.USER,
            principalKey,
            TENANT,
            RESOURCE,
            null,
            Action.READ,
            true,
            GrantBasis.RESOURCE_OWNER,
            null,
            false);
    }
}
