package io.github.joshuamatosdev.security.authz.web.support;

/**
 * Trusted request headers injected at the service boundary.
 *
 * <p>Why this exists: web support isolates header parsing, demo identity resolution, and exception
 * translation at the request boundary.
 */
public final class RequestHeaders {

    /**
     * Header carrying the gateway-validated tenant identifier.
     */
    public static final String TENANT_ID = "X-Tenant-Id";

    private RequestHeaders() {}
}
