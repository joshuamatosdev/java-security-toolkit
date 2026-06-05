package io.github.joshuamatosdev.security.authz.web.config;

import io.github.joshuamatosdev.security.authz.audit.AuthorizationAuditSink;
import io.github.joshuamatosdev.security.authz.audit.Slf4jAuthorizationAuditSink;
import io.github.joshuamatosdev.security.authz.policy.rule.InMemoryPolicyRuleRepository;
import io.github.joshuamatosdev.security.authz.policy.rule.PolicyRuleRepository;
import io.github.joshuamatosdev.security.authz.service.AuthorizationPolicy;
import io.github.joshuamatosdev.security.authz.service.AuthorizationService;
import io.github.joshuamatosdev.security.authz.service.DefaultAuthorizationService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * Composition root for the framework-free decision core. The pure classes carry no Spring
 * annotations so they stay independently testable and liftable; this configuration is the single
 * place that wires them together as beans.
 *
 * <p>Why this exists: security configuration wires the demo route gate and identities in one
 * Spring boundary that is easy to review.
 */
@Configuration
public class AuthorizationConfig {

    @Bean
    Clock authorizationClock() {
        return Clock.systemUTC();
    }

    @Bean
    AuthorizationPolicy authorizationPolicy() {
        return new AuthorizationPolicy();
    }

    @Bean
    PolicyRuleRepository policyRuleRepository() {
        return new InMemoryPolicyRuleRepository();
    }

    @Bean
    AuthorizationAuditSink authorizationAuditSink() {
        return new Slf4jAuthorizationAuditSink();
    }

    @Bean
    AuthorizationService authorizationService(
        final AuthorizationPolicy policy,
        final PolicyRuleRepository policyRuleRepository,
        final AuthorizationAuditSink auditSink,
        final Clock clock) {
        return new DefaultAuthorizationService(policy, policyRuleRepository, auditSink, clock);
    }
}
