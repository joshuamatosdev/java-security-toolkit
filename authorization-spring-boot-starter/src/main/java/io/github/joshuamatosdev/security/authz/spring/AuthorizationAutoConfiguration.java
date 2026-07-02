package io.github.joshuamatosdev.security.authz.spring;

import io.github.joshuamatosdev.security.authz.service.AuthorizationService;
import io.github.joshuamatosdev.security.authz.web.config.AuthorizationConfig;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Import;

/** Auto-configuration entrypoint for the authorization decision core. */
@AutoConfiguration
@ConditionalOnClass(AuthorizationService.class)
@ConditionalOnProperty(
        prefix = "bulwark.authorization",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true)
@ConditionalOnMissingBean(AuthorizationService.class)
@Import(AuthorizationConfig.class)
public class AuthorizationAutoConfiguration {
}
