package io.github.joshuamatosdev.security.authz.spring;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Registers the HTTP 403 mapping for authorization denials in servlet web applications.
 *
 * <p>Without it, {@code AuthorizationService.enforce} denials surface as Boot's default 500 —
 * fail-closed but wrong semantics (server-error alerts, client retries on 5xx). Split from
 * {@link AuthorizationAutoConfiguration} because the decision core itself has no web dependency;
 * this activates only when spring-web is on the classpath and the application is a servlet app.
 */
@AutoConfiguration
@ConditionalOnClass(RestControllerAdvice.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(
        prefix = "bulwark.authorization",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true)
public class AuthorizationWebAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(AuthorizationExceptionHandler.class)
    AuthorizationExceptionHandler authorizationExceptionHandler() {
        return new AuthorizationExceptionHandler();
    }
}
