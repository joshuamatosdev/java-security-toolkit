package io.github.joshuamatosdev.security.tenant.testfixtures;

/**
 * Shared fixture values for tenant-isolation tests.
 *
 * <p>Why this is important to test: shared fixtures must encode the same tenant assumptions in
 * every isolation test, or passing tests could exercise different boundaries.
 */
public final class TenantTestConstants {

    public static final String ACME_DOCUMENT_TITLE = "acme doc";
    public static final String CALLER_SUPPLIED_CREDENTIALS_MESSAGE = "caller-supplied credentials";
    public static final String CLAIM_SECRET = "local-dev-tenant-claim-secret-not-production-32-bytes";
    public static final String DEV_PASSWORD = "local_dev_only";
    public static final String DOCUMENT_BODY_X = "x";
    public static final String DOCUMENT_BODY_Y = "y";
    public static final String GLOBEX_DOCUMENT_TITLE = "globex doc";
    public static final String POSTGRES_USERNAME = "postgres";
    public static final String POSTGRES_PASSWORD = POSTGRES_USERNAME;
    public static final String RUNTIME_USERNAME = "tenant_user";
    public static final String SYSTEM_OPS_USERNAME = "tenant_ops_user";
    public static final String TENANT_CONTEXT_NOT_POPULATED_MESSAGE = "TenantContext not populated";

    private TenantTestConstants() {}
}

