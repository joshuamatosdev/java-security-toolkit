package io.github.joshuamatosdev.security.authz.spring;

import io.github.joshuamatosdev.security.authz.audit.AuthorizationAuditSink;
import io.github.joshuamatosdev.security.authz.audit.Slf4jAuthorizationAuditSink;
import io.github.joshuamatosdev.security.authz.policy.rule.InMemoryPolicyRuleRepository;
import io.github.joshuamatosdev.security.authz.policy.rule.PolicyRuleRepository;
import io.github.joshuamatosdev.security.authz.service.AuthorizationPolicy;
import io.github.joshuamatosdev.security.authz.service.AuthorizationService;
import io.github.joshuamatosdev.security.authz.service.DefaultAuthorizationService;
import java.time.Clock;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Composition root for the framework-free decision core. The pure classes carry no Spring
 * annotations so they stay independently testable and liftable; this configuration is the single
 * place that wires them together as beans, and each bean backs off individually when the
 * application supplies its own.
 *
 * <p>Why this exists: one reviewable Spring boundary wires the decision core without touching it.
 */
@Configuration
public class AuthorizationConfig {

    @Bean
    @ConditionalOnMissingBean(Clock.class)
    Clock authorizationClock() {
        return Clock.systemUTC();
    }

    @Bean
    @ConditionalOnMissingBean(AuthorizationPolicy.class)
    AuthorizationPolicy authorizationPolicy() {
        return new AuthorizationPolicy();
    }

    @Bean
    @ConditionalOnMissingBean(PolicyRuleRepository.class)
    @ConditionalOnProperty(
            prefix = "authorization.demo-policy",
            name = "enabled",
            havingValue = "false",
            matchIfMissing = true)
    PolicyRuleRepository denyAllPolicyRuleRepository() {
        return new DenyAllPolicyRuleRepository();
    }

    @Bean
    @ConditionalOnMissingBean(PolicyRuleRepository.class)
    @ConditionalOnProperty(
            prefix = "authorization.demo-policy", name = "enabled", havingValue = "true")
    PolicyRuleRepository demoPolicyRuleRepository() {
        return new InMemoryPolicyRuleRepository();
    }

    @Bean
    @ConditionalOnMissingBean(AuthorizationAuditSink.class)
    AuthorizationAuditSink authorizationAuditSink() {
        return new Slf4jAuthorizationAuditSink();
    }

    @Bean
    @ConditionalOnMissingBean(AuthorizationService.class)
    AuthorizationService authorizationService(
        final AuthorizationPolicy policy,
        final PolicyRuleRepository policyRuleRepository,
        final AuthorizationAuditSink auditSink,
        final Clock clock) {
        return new DefaultAuthorizationService(policy, policyRuleRepository, auditSink, clock);
    }
}
