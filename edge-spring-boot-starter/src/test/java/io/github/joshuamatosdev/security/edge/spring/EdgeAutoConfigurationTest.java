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
    void doesNotAutoConfigureOutsideReactiveWebApplications() {
        nonReactiveRunner.run(context -> assertThat(context).doesNotHaveBean(EdgeProperties.class));
    }

    @Test
    void canBeDisabled() {
        reactiveRunner
                .withPropertyValues("bulwark.edge.enabled=false")
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
