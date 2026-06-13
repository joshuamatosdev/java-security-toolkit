package io.github.joshuamatosdev.security.edge.spring;

import io.github.joshuamatosdev.security.edge.config.CookiePolicyConfig;
import io.github.joshuamatosdev.security.edge.config.CorsAllowListConfig;
import io.github.joshuamatosdev.security.edge.config.EdgePerimeterProperties;
import io.github.joshuamatosdev.security.edge.csrf.CsrfProtectionConfig;
import io.github.joshuamatosdev.security.edge.filter.BrowserCredentialIsolationFilter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Import;

/**
 * Auto-configuration entrypoint for the edge-perimeter WebFlux security boundary.
 *
 * <p>This entrypoint imports only the credential-plane-agnostic hardening that needs no OAuth2
 * configuration: the CORS allow-list, CSRF double-submit, cookie policy, and the browser/service
 * credential-isolation filter. The two security filter chains are activated by separate
 * auto-configurations that switch on only when their credential infrastructure is present:
 * {@link EdgePerimeterBrowserSecurityAutoConfiguration} when an OAuth2 client registration is
 * configured, and {@link EdgePerimeterServiceApiAutoConfiguration} when a resource-server JWT
 * decoder is configured.
 *
 * <p>Splitting the chains out this way means a reactive application that adds the starter without any
 * OAuth2 configuration gets a clean context (the always-on hardening, no perimeter chains) instead
 * of a context-startup failure on a missing {@code ReactiveClientRegistrationRepository}.
 */
@AutoConfiguration
@ConditionalOnClass(BrowserCredentialIsolationFilter.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ConditionalOnProperty(
        prefix = "bulwark.edge-perimeter",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true)
@EnableConfigurationProperties(EdgePerimeterProperties.class)
@Import({
    CsrfProtectionConfig.class,
    CorsAllowListConfig.class,
    CookiePolicyConfig.class,
    BrowserCredentialIsolationFilter.class
})
public class EdgePerimeterAutoConfiguration {
}
