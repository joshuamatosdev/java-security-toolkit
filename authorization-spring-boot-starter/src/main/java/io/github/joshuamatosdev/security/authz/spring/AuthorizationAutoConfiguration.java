package io.github.joshuamatosdev.security.authz.spring;

import io.github.joshuamatosdev.security.authz.service.AuthorizationService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Import;

/**
 * Auto-configuration entrypoint for the authorization decision core.
 *
 * <p>There is deliberately no class-level {@code @ConditionalOnMissingBean(AuthorizationService)}:
 * each bean in {@link AuthorizationConfig} backs off individually, so an application that replaces
 * one collaborator — the service, the policy, the rule repository, the audit sink, the clock —
 * keeps the reference wiring for everything else.
 */
@AutoConfiguration
@ConditionalOnClass(AuthorizationService.class)
@ConditionalOnProperty(
        prefix = "authorization",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true)
@Import(AuthorizationConfig.class)
public class AuthorizationAutoConfiguration {
}
