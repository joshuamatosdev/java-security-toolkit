package io.github.joshuamatosdev.security.edge.spring;

import io.github.joshuamatosdev.security.edge.chain.BrowserSecurityChainConfig;
import io.github.joshuamatosdev.security.edge.chain.PkceRelaySupport;
import io.github.joshuamatosdev.security.edge.chain.ServiceApiSecurityChainConfig;
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

/** Auto-configuration entrypoint for the edge-perimeter WebFlux security boundary. */
@AutoConfiguration
@ConditionalOnClass(BrowserCredentialIsolationFilter.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ConditionalOnProperty(
        prefix = "glyptodon.edge-perimeter",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true)
@EnableConfigurationProperties(EdgePerimeterProperties.class)
@Import({
    BrowserSecurityChainConfig.class,
    ServiceApiSecurityChainConfig.class,
    PkceRelaySupport.class,
    CsrfProtectionConfig.class,
    CorsAllowListConfig.class,
    CookiePolicyConfig.class,
    BrowserCredentialIsolationFilter.class
})
public class EdgePerimeterAutoConfiguration {
}
