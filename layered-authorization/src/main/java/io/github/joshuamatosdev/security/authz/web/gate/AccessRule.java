package io.github.joshuamatosdev.security.authz.web.gate;

import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;

import java.util.List;

/**
 * Binds a {@link SecurityUrlGroup} (optionally narrowed to one HTTP method) to the role(s) allowed
 * to reach it. {@link #RESTRICTED_RULES} is the whole coarse authorization table; applying it, then
 * denying everything else, is what makes the request gate deny-by-default: a route in no rule is
 * {@code denyAll()}, never an implicit permit.
 */
public record AccessRule(SecurityUrlGroup group, @Nullable HttpMethod method, List<String> roles) {

    /**
     * The coarse authorization table. Documents need a member or admin; admin routes need an admin.
     */
    public static final List<AccessRule> RESTRICTED_RULES = List.of(
        AccessRule.any(SecurityUrlGroup.DOCUMENTS, "MEMBER", "PLATFORM_ADMIN"),
        AccessRule.any(SecurityUrlGroup.ADMIN, "PLATFORM_ADMIN"));

    public AccessRule {
        roles = List.copyOf(roles);
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
        if (roleValues.length == 0) {
            authorized.authenticated();
        } else if (roleValues.length == 1) {
            authorized.hasRole(roleValues[0]);
        } else {
            authorized.hasAnyRole(roleValues);
        }
    }
}
