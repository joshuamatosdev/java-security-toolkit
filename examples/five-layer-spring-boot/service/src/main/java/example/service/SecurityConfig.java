package example.service;

import java.util.Collection;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Stateless bearer-token API security with the coarse route gate — the first of the two
 * authorization gates. A route matching no rule is denied; the fine-grained per-resource decision
 * (the second gate) runs inside {@link DocumentController} through the authorization starter.
 *
 * <p>CSRF protection is disabled because this API authenticates every request with a bearer JWT and
 * issues no session cookie a cross-site request could ride on. Browser-session concerns (cookies,
 * CORS, CSRF, headers) belong to the {@code bff} subproject's edge perimeter, not to this service.
 */
@Configuration
@EnableWebSecurity
class SecurityConfig {

    private static final String ROLES_CLAIM = "roles";
    private static final String ROLE_AUTHORITY_PREFIX = "ROLE_";

    @Bean
    SecurityFilterChain apiSecurity(final HttpSecurity http) throws Exception {
        return http.csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers("/documents", "/documents/**")
                        .hasAnyRole("MEMBER", "PLATFORM_ADMIN")
                        .anyRequest()
                        .denyAll())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt ->
                        jwt.jwtAuthenticationConverter(rolesConverter())))
                .build();
    }

    /**
     * Maps the JWT {@code roles} claim to {@code ROLE_*} authorities. Same contract as the edge
     * module's service plane: the claim carries <b>bare</b> role names ({@code "MEMBER"}) and this
     * converter adds the single {@code ROLE_} prefix, so an issuer minting already-prefixed values
     * fails closed instead of being silently accepted.
     */
    private static JwtAuthenticationConverter rolesConverter() {
        final JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(SecurityConfig::roleAuthorities);
        return converter;
    }

    private static Collection<GrantedAuthority> roleAuthorities(final Jwt jwt) {
        if (!(jwt.getClaim(ROLES_CLAIM) instanceof Collection<?> roles)
                || roles.stream().anyMatch(role -> !(role instanceof String))) {
            return List.of();
        }
        return roles.stream()
                .map(String.class::cast)
                .map(role -> (GrantedAuthority) new SimpleGrantedAuthority(ROLE_AUTHORITY_PREFIX + role))
                .toList();
    }
}
