package io.github.joshuamatosdev.security.authz.web.support;

/**
 * Names of caller-supplied request headers read at the service boundary.
 *
 * <p>These are <em>untrusted</em> boundary claims, not authority: the tenant header is
 * cross-checked against the context resolved from the authenticated principal and rejected on
 * mismatch. It never selects or creates tenant identity.
 *
 * <p>Why this exists: web support isolates header parsing, demo identity resolution, and exception
 * translation at the request boundary.
 */
public final class RequestHeaders {

    /**
     * Header carrying the caller's claimed tenant identifier, validated against the resolved
     * request context.
     */
    public static final String TENANT_ID = "X-Tenant-Id";

    private RequestHeaders() {}
}
