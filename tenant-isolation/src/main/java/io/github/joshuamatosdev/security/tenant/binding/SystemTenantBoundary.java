package io.github.joshuamatosdev.security.tenant.binding;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a type permitted to reason about the system-operations tenant boundary — the
 * narrow set of components allowed to route through the system-ops bypass role. Used as an
 * architecture-test anchor: only annotated types may touch the bypass path.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface SystemTenantBoundary {}
