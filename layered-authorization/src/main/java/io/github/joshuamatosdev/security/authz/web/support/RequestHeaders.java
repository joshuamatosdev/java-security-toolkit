package io.github.joshuamatosdev.security.authz.web.support;

/**
 * Trusted request headers injected at the service boundary.
 */
public final class RequestHeaders {

    /**
     * Header carrying the gateway-validated tenant identifier.
     */
    public static final String TENANT_ID = "X-Tenant-Id";

    /**
     * Header carrying the optional gateway-validated organization identifier.
     */
    public static final String ORGANIZATION_ID = "X-Org-Id";

    private RequestHeaders() {}
}
