package io.github.joshuamatosdev.security.authz.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import io.github.joshuamatosdev.security.authz.audit.AuthorizationAuditSink;
import io.github.joshuamatosdev.security.authz.policy.Action;
import io.github.joshuamatosdev.security.authz.policy.PolicyScopeType;
import io.github.joshuamatosdev.security.authz.policy.RoleAssignment;
import io.github.joshuamatosdev.security.authz.policy.Roles;
import io.github.joshuamatosdev.security.authz.policy.rule.InMemoryPolicyRuleRepository;
import io.github.joshuamatosdev.security.authz.policy.rule.PolicyRuleRepository;
import io.github.joshuamatosdev.security.authz.service.AuthorizationPolicy;
import io.github.joshuamatosdev.security.authz.service.AuthorizationService;
import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.TenantId;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

class AuthorizationAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AuthorizationAutoConfiguration.class));

    @Test
    void autoConfiguresAuthorizationService() {
        contextRunner.run(context -> assertThat(context).hasSingleBean(AuthorizationService.class));
    }

    @Test
    void defaultRuleRepositoryDeniesMemberAccess() {
        contextRunner.run(context -> {
            final PolicyRuleRepository repository = context.getBean(PolicyRuleRepository.class);
            final TenantId tenant = new TenantId(UUID.randomUUID());
            final OrganizationId organization = new OrganizationId(UUID.randomUUID());

            assertThat(repository.effectivePolicyFor(tenant).allowingScope(
                            Set.of(RoleAssignment.organization(Roles.MEMBER, organization)),
                            organization,
                            null,
                            Action.READ))
                    .isEmpty();
        });
    }

    @Test
    void demoPolicyRequiresExplicitOptIn() {
        contextRunner
                .withPropertyValues("authorization.demo-policy.enabled=true")
                .run(context -> {
                    final PolicyRuleRepository repository = context.getBean(PolicyRuleRepository.class);
                    final TenantId tenant = new TenantId(UUID.randomUUID());
                    final OrganizationId organization = new OrganizationId(UUID.randomUUID());

                    assertThat(repository).isInstanceOf(InMemoryPolicyRuleRepository.class);
                    assertThat(repository.effectivePolicyFor(tenant).allowingScope(
                                    Set.of(RoleAssignment.organization(Roles.MEMBER, organization)),
                                    organization,
                                    null,
                                    Action.READ))
                            .contains(PolicyScopeType.ORGANIZATION);
                });
    }

    @Test
    void backsOffWhenApplicationProvidesAnAuditSink() {
        contextRunner
                .withUserConfiguration(CustomAuditSinkConfiguration.class)
                .run(context -> {
                    assertThat(context).hasSingleBean(AuthorizationAuditSink.class);
                    assertThat(context).hasSingleBean(AuthorizationService.class);
                });
    }

    @Test
    void customRuleRepositoryOverridesBothStarterModes() {
        contextRunner
                .withUserConfiguration(CustomRuleRepositoryConfiguration.class)
                .withPropertyValues("authorization.demo-policy.enabled=true")
                .run(context -> {
                    assertThat(context).hasSingleBean(PolicyRuleRepository.class);
                    assertThat(context.getBean(PolicyRuleRepository.class))
                            .isSameAs(context.getBean(CustomRuleRepositoryConfiguration.class).repository);
                });
    }

    @Test
    void canBeDisabled() {
        contextRunner
                .withPropertyValues("authorization.enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(AuthorizationService.class));
    }

    @Test
    void keepsTheReferenceWiringWhenTheApplicationReplacesTheService() {
        // The metadata promise: each bean is individually replaceable. Replacing the service must
        // back off that one bean and leave policy, rule repository, and audit sink available for
        // the custom service to inject.
        contextRunner
                .withUserConfiguration(CustomServiceConfiguration.class)
                .run(context -> {
                    assertThat(context).hasSingleBean(AuthorizationService.class);
                    assertThat(context.getBean(AuthorizationService.class))
                            .isSameAs(context.getBean(CustomServiceConfiguration.class).service);
                    assertThat(context).hasSingleBean(AuthorizationPolicy.class);
                    assertThat(context).hasSingleBean(PolicyRuleRepository.class);
                    assertThat(context).hasSingleBean(AuthorizationAuditSink.class);
                });
    }

    @Test
    void registersTheDenialAdviceInServletWebApplications() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        AuthorizationAutoConfiguration.class, AuthorizationWebAutoConfiguration.class))
                .run(context -> assertThat(context).hasSingleBean(AuthorizationExceptionHandler.class));
    }

    @Test
    void keepsNonWebApplicationsFreeOfTheDenialAdvice() {
        contextRunner
                .withConfiguration(AutoConfigurations.of(AuthorizationWebAutoConfiguration.class))
                .run(context -> assertThat(context).doesNotHaveBean(AuthorizationExceptionHandler.class));
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomAuditSinkConfiguration {
        @Bean
        AuthorizationAuditSink customAuditSink() {
            return record -> { };
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomRuleRepositoryConfiguration {
        final PolicyRuleRepository repository = mock(PolicyRuleRepository.class);

        @Bean
        PolicyRuleRepository customPolicyRuleRepository() {
            return repository;
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomServiceConfiguration {
        final AuthorizationService service = mock(AuthorizationService.class);

        @Bean
        AuthorizationService customAuthorizationService() {
            return service;
        }
    }
}
