package io.github.joshuamatosdev.security.edge.spring;

import io.github.joshuamatosdev.security.edge.chain.ServiceApiSecurityChainConfig;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

/**
 * Activates the service-plane (OAuth2 resource server) security chain only when a JWT decoder is
 * configured.
 *
 * <p>{@link ServiceApiSecurityChainConfig} builds a {@code SecurityWebFilterChain} that calls
 * {@code oauth2ResourceServer().jwt()}, which requires a {@link ReactiveJwtDecoder} — created by
 * Spring Boot from {@code spring.security.oauth2.resourceserver.jwt.*}. This auto-configuration is
 * ordered after {@code ReactiveOAuth2ResourceServerAutoConfiguration} and gates on that bean, so a
 * reactive consumer that has not configured a resource server can add the starter without a
 * context-startup failure — the service chain simply does not activate.
 *
 * <p>{@link EnableWebFluxSecurity} is declared here so the {@code ServerHttpSecurity} infrastructure
 * is present even when only the service plane is configured (the browser chain carries its own copy;
 * Spring de-duplicates the imported security configuration when both planes are active).
 */
@AutoConfiguration(
        afterName =
            "org.springframework.boot.security.oauth2.server.resource.autoconfigure.reactive.ReactiveOAuth2ResourceServerAutoConfiguration")
@ConditionalOnClass(ReactiveJwtDecoder.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ConditionalOnProperty(
        prefix = "edge",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true)
@ConditionalOnBean(ReactiveJwtDecoder.class)
@EnableWebFluxSecurity
@Import(ServiceApiSecurityChainConfig.class)
public class EdgeServiceApiAutoConfiguration {
}
