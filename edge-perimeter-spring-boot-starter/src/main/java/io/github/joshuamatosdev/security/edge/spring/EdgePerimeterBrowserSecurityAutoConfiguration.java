package io.github.joshuamatosdev.security.edge.spring;

import io.github.joshuamatosdev.security.edge.chain.BrowserSecurityChainConfig;
import io.github.joshuamatosdev.security.edge.chain.PkceRelaySupport;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;

/**
 * Activates the browser-plane OIDC login security chain only when an OAuth2 client registration is
 * configured.
 *
 * <p>{@link BrowserSecurityChainConfig} and {@link PkceRelaySupport} both require a
 * {@link ReactiveClientRegistrationRepository}, which Spring Boot creates from
 * {@code spring.security.oauth2.client.registration.*}. This auto-configuration is ordered after
 * {@code ReactiveOAuth2ClientAutoConfiguration} so that bean is registered first, then gates on its
 * presence: a reactive consumer that has not configured an OAuth2 client can add the starter without
 * a context-startup failure — the browser login chain simply does not activate.
 */
@AutoConfiguration(
        afterName =
            "org.springframework.boot.autoconfigure.security.oauth2.client.reactive.ReactiveOAuth2ClientAutoConfiguration")
@ConditionalOnClass(ReactiveClientRegistrationRepository.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ConditionalOnProperty(
        prefix = "bulwark.edge-perimeter",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true)
@ConditionalOnBean(ReactiveClientRegistrationRepository.class)
@Import({BrowserSecurityChainConfig.class, PkceRelaySupport.class})
public class EdgePerimeterBrowserSecurityAutoConfiguration {
}
