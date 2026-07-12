package io.github.joshuamatosdev.security.authz.request;

import io.github.joshuamatosdev.security.authz.principal.PrincipalType;
import io.github.joshuamatosdev.security.shared.ResourceId;
import io.github.joshuamatosdev.security.shared.TenantId;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Protected Resource test coverage.
 *
 * <p>Why this is important to test: resource facts drive fine-grained policy, so malformed or
 * ambiguous facts would authorize the wrong actor.
 */
class ProtectedResourceTest {

    private static final ResourceId RESOURCE =
        new ResourceId(UUID.fromString("33333333-3333-3333-3333-333333333333"));
    private static final TenantId TENANT =
        new TenantId(UUID.fromString("11111111-1111-1111-1111-111111111111"));

    @Test
    void ownerPrincipalKeyMustNotIncludeLeadingOrTrailingWhitespace() {
        assertThatThrownBy(() -> resource(" alice"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("ownerPrincipalKey must not include leading or trailing whitespace");

        assertThatThrownBy(() -> resource("alice "))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("ownerPrincipalKey must not include leading or trailing whitespace");
    }

    @Test
    void ownerPrincipalKeyMustNotContainControlCharacters() {
        assertThatThrownBy(() -> resource("alice\nforged"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("ownerPrincipalKey must not contain control characters");
    }

    @Test
    void typedIdsRejectNonCanonicalUuidText() {
        assertThatThrownBy(() -> TenantId.fromString("1-1-1-1-1"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("TenantId must be a canonical UUID");

        assertThatThrownBy(() -> ResourceId.fromString("1-1-1-1-1"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("ResourceId must be a canonical UUID");
    }

    private static ProtectedResource resource(final String ownerPrincipalKey) {
        return ProtectedResource.owned(RESOURCE, TENANT, null, PrincipalType.USER, ownerPrincipalKey);
    }
}
