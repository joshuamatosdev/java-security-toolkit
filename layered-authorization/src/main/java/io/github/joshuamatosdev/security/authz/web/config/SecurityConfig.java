package io.github.joshuamatosdev.security.authz.web.config;

import io.github.joshuamatosdev.security.authz.policy.Roles;
import io.github.joshuamatosdev.security.authz.web.document.DocumentController;
import io.github.joshuamatosdev.security.authz.web.support.DemoAccounts;
import io.github.joshuamatosdev.security.authz.web.gate.AccessRule;
import io.github.joshuamatosdev.security.authz.web.gate.SecurityUrlGroup;
import jakarta.servlet.DispatcherType;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * The coarse request gate (Layer 2, edge of this service). The gate
 * applies the {@link AccessRule#RESTRICTED_RULES} table, permits the public groups, and then
 * <strong>denies everything else</strong> — a route that matches no rule is rejected, so adding an
 * endpoint without a rule fails closed instead of being silently public.
 *
 * <p>Fine-grained, resource-aware decisions are NOT made here (the gate cannot see the resource);
 * they are made in the service via {@code AuthorizationService.enforce} — see {@link DocumentController}.
 */
@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(final HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> {
                // Preserve MVC-generated 400/404/405 responses instead of rewriting /error dispatches as 403.
                auth.dispatcherTypeMatchers(DispatcherType.ERROR).permitAll();
                for (final SecurityUrlGroup group : SecurityUrlGroup.values()) {
                    if (group.isPublic()) {
                        auth.requestMatchers(group.publicMethod(), group.securityUrls()).permitAll();
                    }
                }
                AccessRule.RESTRICTED_RULES.forEach(rule -> AccessRule.applyRule(auth, rule));
                // Deny-by-default: anything not matched above is rejected.
                auth.anyRequest().denyAll();
            })
            // This surface authenticates per-request (HTTP Basic here, a bearer token in production)
            // and carries no ambient session cookie, so CSRF does not apply. Browser-session CSRF is
            // a perimeter concern demonstrated in the edge-perimeter module.
            .csrf(AbstractHttpConfigurer::disable)
            .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    /**
     * Two demo accounts so the module is runnable end-to-end. The passwords are obvious local-only
     * placeholders ({@code {noop}} = no hashing) — never a real or production-shaped credential.
     *
     * <p>Gated behind {@code showcase.demo-identity=true}, which defaults to off. A deployment that
     * does not explicitly opt in gets no in-memory users, so this demo credential source can never
     * reach production by omission — the deployment must supply its own {@link UserDetailsService}.
     */
    @Bean
    @ConditionalOnProperty(name = "showcase.demo-identity", havingValue = "true")
    UserDetailsService users() {
        final UserDetails member =
            User.withUsername(DemoAccounts.MEMBER_USERNAME).password(DemoAccounts.PASSWORD).roles(Roles.MEMBER).build();
        final UserDetails admin =
            User.withUsername(DemoAccounts.ADMIN_USERNAME).password(DemoAccounts.PASSWORD).roles(Roles.PLATFORM_ADMIN).build();
        return new InMemoryUserDetailsManager(member, admin);
    }
}
