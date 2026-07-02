package io.github.joshuamatosdev.security.edge.chain;

/**
 * Route → authority map for the browser plane, kept as named constants so the rules read as a table
 * and the ordering invariant is explicit.
 *
 * <p>The load-bearing detail is order. {@link #AUDIT_EXPORT_PATHS} is a narrow exception that admits
 * the auditor role <em>in addition to</em> admin, and it must be registered <b>before</b> the broad
 * {@link #ADMIN_PATHS} rule. Spring Security evaluates {@code authorizeExchange} matchers
 * first-match-wins: if the broad admin-only rule were registered first, an auditor hitting
 * {@code /api/admin/audit-export} would match the admin rule, be denied, and never reach its own
 * exception. Narrow-before-broad is the whole lesson.
 *
 * <p>Why this exists: separate security chains encode browser-session and service-token
 * authentication so one credential model cannot authorize the other.
 */
public final class RouteAuthorities {

  private RouteAuthorities() {}

  /** Anonymous surface: liveness/status the SPA polls before login. */
  public static final String[] PUBLIC_PATHS = {"/api/public/**"};

  /** Generic authenticated browser surface. */
  public static final String[] DOCUMENT_PATHS = {"/api/documents", "/api/documents/**"};

  /**
   * Audit export — a narrow exception under {@code /api/admin} that auditors may reach too. MUST be
   * registered before {@link #ADMIN_PATHS}.
   */
  public static final String[] AUDIT_EXPORT_PATHS = {"/api/admin/audit-export"};

  public static final String[] AUDIT_EXPORT_AUTHORITIES = {"ROLE_auditor", "ROLE_admin"};

  /** The broad administrative surface — admin only. Registered after the narrow exception. */
  public static final String[] ADMIN_PATHS = {"/api/admin/**"};

  public static final String[] ADMIN_AUTHORITIES = {"ROLE_admin"};
}
