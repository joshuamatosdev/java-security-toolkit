package io.github.joshuamatosdev.security.authz.request;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.authz.policy.RoleAssignment;
import io.github.joshuamatosdev.security.authz.policy.Roles;
import io.github.joshuamatosdev.security.authz.principal.UserPrincipal;
import io.github.joshuamatosdev.security.shared.TenantId;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Request Context test coverage.
 *
 * <p>Why this is important to test: malformed request facts must fail at the authorization boundary
 * with explicit contracts, not incidental JDK collection errors.
 */
class RequestContextTest {

    private static final UserPrincipal PRINCIPAL =
            new UserPrincipal("alice", "alice@example.test", 1L);
    private static final TenantId TENANT =
            TenantId.fromString("11111111-1111-1111-1111-111111111111");

    @Test
    void roleAssignmentsMustNotBeNull() {
        assertThatThrownBy(() -> context(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("roleAssignments must not be null");
    }

    @Test
    void roleAssignmentsMustNotContainNullEntries() {
        final Set<RoleAssignment> assignments = new HashSet<>();
        assignments.add(null);

        assertThatThrownBy(() -> context(assignments))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("roleAssignment must not be null");
    }

    private static RequestContext context(final Set<RoleAssignment> assignments) {
        return new RequestContext(
                PRINCIPAL,
                TENANT,
                null,
                assignments,
                UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
    }
}
