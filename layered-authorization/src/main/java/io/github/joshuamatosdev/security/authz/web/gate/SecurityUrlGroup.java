package io.github.joshuamatosdev.security.authz.web.gate;

import io.github.joshuamatosdev.security.authz.web.document.DocumentRoutes;
import io.github.joshuamatosdev.security.authz.web.health.HealthRoutes;
import org.springframework.http.HttpMethod;

import java.util.List;
import java.util.Objects;

/**
 * The coarse, request-level URL map: each group is a set of path patterns plus an access
 * classification. This is the cheap first gate that runs before any domain code. It is
 * <em>necessary but not sufficient</em> — it can see the route and the caller's roles, but not the
 * resource, so object-level access is decided later by the fine-grained policy.
 *
 * <p>Why this exists: the route gate is the coarse deny-by-default layer that blocks impossible
 * requests before resource policy work begins.
 */
public enum SecurityUrlGroup {
    PUBLIC_HEALTH(Access.PUBLIC_GET, HealthRoutes.HEALTH_PATH),
    DOCUMENTS(Access.RESTRICTED, DocumentRoutes.DOCUMENTS_PATH, DocumentRoutes.DOCUMENTS_DESCENDANTS_PATTERN),
    ADMIN(Access.RESTRICTED, "/api/admin/**");

    private final Access access;
    private final List<String> patterns;

    SecurityUrlGroup(final Access access, final String... patterns) {
        this.access = access;
        this.patterns = List.of(patterns);
    }

    public String[] securityUrls() {
        return patterns.toArray(String[]::new);
    }

    public boolean isPublic() {
        return access != Access.RESTRICTED;
    }

    public HttpMethod publicMethod() {
        return Objects.requireNonNull(access.publicMethod(), "restricted groups do not have a public method");
    }

    public enum Access {
        PUBLIC_GET(HttpMethod.GET),
        RESTRICTED(null);

        private final HttpMethod publicMethod;

        Access(final HttpMethod publicMethod) {
            this.publicMethod = publicMethod;
        }

        HttpMethod publicMethod() {
            return publicMethod;
        }
    }
}
