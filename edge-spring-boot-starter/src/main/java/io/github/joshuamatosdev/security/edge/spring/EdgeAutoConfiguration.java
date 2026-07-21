package io.github.joshuamatosdev.security.edge.spring;

import io.github.joshuamatosdev.security.edge.config.CookiePolicyConfig;
import io.github.joshuamatosdev.security.edge.config.CorsAllowListConfig;
import io.github.joshuamatosdev.security.edge.config.EdgeProperties;
import io.github.joshuamatosdev.security.edge.chain.FallbackDenySecurityChainConfig;
import io.github.joshuamatosdev.security.edge.csrf.CsrfProtectionConfig;
import io.github.joshuamatosdev.security.edge.filter.BrowserCredentialIsolationFilter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Import;

/**
 * Auto-configuration entrypoint for the edge WebFlux security boundary.
 *
 * <p>This entrypoint imports only the credential-plane-agnostic hardening that needs no OAuth2
 * configuration: the CORS allow-list, CSRF double-submit, cookie policy, and the browser/service
 * credential-isolation filter and an order-last deny chain. The two credential-bearing security
 * filter chains are activated by separate
 * auto-configurations that switch on only when their credential infrastructure is present:
 * {@link EdgeBrowserSecurityAutoConfiguration} when an OAuth2 client registration is
 * configured, and {@link EdgeServiceApiAutoConfiguration} when a resource-server JWT
 * decoder is configured.
 *
 * <p>Splitting the chains out this way means a reactive application that adds the starter without any
 * OAuth2 configuration gets a clean, fail-closed context instead of a context-startup failure on a
 * missing {@code ReactiveClientRegistrationRepository}. The fallback chain denies every request
 * until a credential plane owns it.
 */
// Ordered before Boot's WebSessionIdResolverAutoConfiguration: both define a bean named
// webSessionIdResolver, and Boot's carries @ConditionalOnMissingBean while the edge policy bean is
// unconditional (hardened cookie flags are the point of the starter). Registering the edge bean
// first lets Boot's back off; the reverse order fails the context with a bean-override error.
@AutoConfiguration(
        beforeName =
            "org.springframework.boot.webflux.autoconfigure.WebSessionIdResolverAutoConfiguration")
@ConditionalOnClass(BrowserCredentialIsolationFilter.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ConditionalOnProperty(
        prefix = "edge",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true)
@EnableConfigurationProperties(EdgeProperties.class)
@Import({
    CsrfProtectionConfig.class,
    CorsAllowListConfig.class,
    CookiePolicyConfig.class,
    BrowserCredentialIsolationFilter.class,
    FallbackDenySecurityChainConfig.class
})
public class EdgeAutoConfiguration {
}
