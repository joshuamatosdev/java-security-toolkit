package io.github.joshuamatosdev.security.edge.spring;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.edge.config.EdgeProperties;
import io.github.joshuamatosdev.security.edge.filter.BrowserCredentialIsolationFilter;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRepository;
import org.springframework.web.cors.reactive.CorsConfigurationSource;

class EdgeAutoConfigurationTest {

    private final ApplicationContextRunner nonReactiveRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(EdgeAutoConfiguration.class));

    private final ReactiveWebApplicationContextRunner reactiveRunner = new ReactiveWebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    EdgeAutoConfiguration.class,
                    EdgeBrowserSecurityAutoConfiguration.class,
                    EdgeServiceApiAutoConfiguration.class));

    @Test
    void winsTheWebSessionIdResolverNameAgainstBootsOwnAutoConfiguration() {
        // Boot's WebSessionIdResolverAutoConfiguration registers an unconditional-name twin:
        // a bean also called webSessionIdResolver, guarded only by @ConditionalOnMissingBean.
        // The starter must be ordered before it so the hardened cookie resolver registers first
        // and Boot's backs off — the reverse order fails a real consumer boot with a
        // BeanDefinitionOverrideException (found by the five-layer example's bff).
        new ReactiveWebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        org.springframework.boot.webflux.autoconfigure
                                .WebSessionIdResolverAutoConfiguration.class,
                        EdgeAutoConfiguration.class))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context)
                            .hasSingleBean(org.springframework.web.server.session.WebSessionIdResolver.class);
                    // The edge policy bean, not Boot's: it pins Secure/HttpOnly/SameSite=Lax.
                    assertThat(context.getBeanDefinitionNames())
                            .contains("webSessionIdResolver");
                    assertThat(context.getBean(
                                    org.springframework.web.server.session.WebSessionIdResolver.class))
                            .isInstanceOf(org.springframework.web.server.session.CookieWebSessionIdResolver.class);
                });
    }

    @Test
    void doesNotAutoConfigureOutsideReactiveWebApplications() {
        nonReactiveRunner.run(context -> assertThat(context).doesNotHaveBean(EdgeProperties.class));
    }

    @Test
    void canBeDisabled() {
        reactiveRunner
                .withPropertyValues("edge.enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(EdgeProperties.class));
    }

    @Test
    void registersTheCredentialPlaneAgnosticPerimeterBeansInAReactiveApp() {
        // The always-on hardening must be wired even before any OAuth2 plane is configured. This is the
        // regression guard the starter previously lacked: dropping any of these from the @Import list
        // (for example the credential-isolation filter) now fails this test instead of silently
        // shipping a weaker perimeter to consumers.
        reactiveRunner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(EdgeProperties.class);
            assertThat(context).hasSingleBean(BrowserCredentialIsolationFilter.class);
            assertThat(context).hasSingleBean(CorsConfigurationSource.class);
            assertThat(context).hasSingleBean(ServerCsrfTokenRepository.class);
        });
    }

    @Test
    void registersBothSecurityChainsAfterBootCreatesTheirOauth2Dependencies() {
        new ReactiveWebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        org.springframework.boot.security.oauth2.client.autoconfigure.reactive
                                .ReactiveOAuth2ClientAutoConfiguration.class,
                        org.springframework.boot.security.oauth2.server.resource.autoconfigure.reactive
                                .ReactiveOAuth2ResourceServerAutoConfiguration.class,
                        EdgeAutoConfiguration.class,
                        EdgeBrowserSecurityAutoConfiguration.class,
                        EdgeServiceApiAutoConfiguration.class))
                .withPropertyValues(
                        "spring.security.oauth2.client.registration.idp.client-id=edge-test",
                        "spring.security.oauth2.client.registration.idp.client-authentication-method=none",
                        "spring.security.oauth2.client.registration.idp.authorization-grant-type=authorization_code",
                        "spring.security.oauth2.client.registration.idp.redirect-uri={baseUrl}/login/oauth2/code/idp",
                        "spring.security.oauth2.client.registration.idp.scope=openid,profile",
                        "spring.security.oauth2.client.provider.idp.authorization-uri=https://idp.acme.example/authorize",
                        "spring.security.oauth2.client.provider.idp.token-uri=https://idp.acme.example/token",
                        "spring.security.oauth2.client.provider.idp.jwk-set-uri=https://idp.acme.example/jwks",
                        "spring.security.oauth2.client.provider.idp.user-info-uri=https://idp.acme.example/userinfo",
                        "spring.security.oauth2.client.provider.idp.user-name-attribute=sub",
                        "spring.security.oauth2.resourceserver.jwt.jwk-set-uri=https://idp.acme.example/jwks",
                        "edge.identity.issuer-uri=https://idp.acme.example",
                        "edge.service-jwt.audiences=edge-service-api",
                        "edge.cors.allowed-origins=https://app.acme.example")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context)
                            .hasSingleBean(org.springframework.security.oauth2.client.registration
                                    .ReactiveClientRegistrationRepository.class);
                    assertThat(context)
                            .hasSingleBean(org.springframework.security.oauth2.jwt.ReactiveJwtDecoder.class);
                    assertThat(context).hasBean("browserSecurityFilterChain");
                    assertThat(context).hasBean("serviceApiSecurityFilterChain");
                });
    }

    @Test
    void degradesWithoutOauth2ConfigurationInsteadOfFailingContextStartup() {
        // A reactive app that adds the starter with no OAuth2 client or resource-server configuration
        // must start cleanly (the previous behavior was a NoSuchBeanDefinitionException on
        // ReactiveClientRegistrationRepository). Neither security filter chain activates.
        reactiveRunner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(EdgeProperties.class);
            assertThat(context).doesNotHaveBean("browserSecurityFilterChain");
            assertThat(context).doesNotHaveBean("authorizationRequestResolver");
            assertThat(context).doesNotHaveBean("serviceApiSecurityFilterChain");
        });
    }
}
