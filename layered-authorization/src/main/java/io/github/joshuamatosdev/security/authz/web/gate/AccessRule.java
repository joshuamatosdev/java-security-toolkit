package io.github.joshuamatosdev.security.authz.web.gate;

import io.github.joshuamatosdev.security.authz.policy.Roles;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;

import java.util.List;
import java.util.Objects;

/**
 * Binds a {@link SecurityUrlGroup} (optionally narrowed to one HTTP method) to the role(s) allowed
 * to reach it. {@link #RESTRICTED_RULES} is the whole coarse authorization table; applying it, then
 * denying everything else, is what makes the request gate deny-by-default: a route in no rule is
 * {@code denyAll()}, never an implicit permit.
 *
 * <p>Why this exists: the route gate is the coarse deny-by-default layer that blocks impossible
 * requests before resource policy work begins.
 */
public record AccessRule(SecurityUrlGroup group, @Nullable HttpMethod method, List<String> roles) {

    private static final String ROLE_PREFIX = "ROLE_";

    /**
     * The coarse authorization table. Documents need a member or admin; admin routes need an admin.
     */
    public static final List<AccessRule> RESTRICTED_RULES = List.of(
        AccessRule.any(SecurityUrlGroup.DOCUMENTS, Roles.MEMBER, Roles.PLATFORM_ADMIN),
        AccessRule.any(SecurityUrlGroup.ADMIN, Roles.PLATFORM_ADMIN));

    public AccessRule {
        Objects.requireNonNull(group, "group must not be null");
        Objects.requireNonNull(roles, "roles must not be null");
        if (roles.isEmpty()) {
            throw new IllegalArgumentException("restricted access rules must name at least one role");
        }
        roles = roles.stream().map(AccessRule::requireBareRole).toList();
    }

    public static AccessRule any(final SecurityUrlGroup group, final String... roles) {
        return new AccessRule(group, null, List.of(roles));
    }

    public static AccessRule method(final SecurityUrlGroup group, final HttpMethod method, final String... roles) {
        return new AccessRule(group, method, List.of(roles));
    }

    public static void applyRule(
        final AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry,
        final AccessRule rule) {
        final String[] urls = rule.group().securityUrls();
        final var authorized =
            rule.method() == null ? registry.requestMatchers(urls) : registry.requestMatchers(rule.method(), urls);
        final String[] roleValues = rule.roles().toArray(String[]::new);
        if (roleValues.length == 1) {
            authorized.hasRole(roleValues[0]);
        } else {
            authorized.hasAnyRole(roleValues);
        }
    }

    private static String requireBareRole(final String role) {
        Objects.requireNonNull(role, "role must not be null");
        if (role.isBlank()) {
            throw new IllegalArgumentException("role must not be blank");
        }
        if (!role.equals(role.strip())) {
            throw new IllegalArgumentException("role must not include leading or trailing whitespace");
        }
        if (role.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("role must not contain control characters");
        }
        if (role.startsWith(ROLE_PREFIX)) {
            throw new IllegalArgumentException("role must be bare; do not include " + ROLE_PREFIX);
        }
        return role;
    }
}
