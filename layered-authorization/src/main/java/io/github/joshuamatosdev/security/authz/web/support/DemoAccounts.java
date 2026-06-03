package io.github.joshuamatosdev.security.authz.web.support;

/**
 * Local-only demo identities used by the runnable authorization showcase.
 */
public final class DemoAccounts {

    public static final String MEMBER_USERNAME = "member";
    public static final String ADMIN_USERNAME = "admin";
    public static final String MALICIOUS_USERNAME = "mallory";
    public static final String PASSWORD = "{noop}local-dev-only";
    public static final String EMAIL_DOMAIN = "@example.test";

    private DemoAccounts() {}
}
