package io.github.joshuamatosdev.security.authz.web.support;

/**
 * Local-only demo identities used by the runnable authorization showcase.
 *
 * <p>Why this exists: web support isolates header parsing, demo identity resolution, and exception
 * translation at the request boundary.
 */
public final class DemoAccounts {

    public static final String MEMBER_USERNAME = "member";
    public static final String ADMIN_USERNAME = "admin";
    public static final String MALICIOUS_USERNAME = "mallory";

    /** A non-interactive (machine) caller, keyed by its client id rather than a human username. */
    public static final String SERVICE_USERNAME = "svc-report";

    public static final String PASSWORD = "{noop}local-dev-only";
    public static final String EMAIL_DOMAIN = "@example.test";

    private DemoAccounts() {}
}
