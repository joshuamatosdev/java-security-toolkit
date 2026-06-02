package io.github.joshuamatosdev.security.tenant;

/**
 * Distinguishes a long-lived binding from a scoped one.
 *
 * <ul>
 *   <li>{@code UNBOUNDED} — set for the lifetime of a request (e.g. by an inbound filter) via
 *       {@link TenantContext#set(TenantId)}.
 *   <li>{@code BOUNDED} — set only for the duration of a {@code runAs}/{@code supplyAs} block and
 *       then restored.
 * </ul>
 */
enum TenantBindingScope {
    BOUNDED,
    UNBOUNDED
}
