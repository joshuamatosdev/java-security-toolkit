package io.github.joshuamatosdev.security.authz.decision;

/**
 * Why an access was granted — recorded in the audit trail so an allow is never unexplained.
 *
 * <p>Why this exists: sealed decision types make allow and deny outcomes carry their enforcement
 * and audit rationale explicitly.
 */
public enum GrantBasis {
    /**
     * A tenant-scoped admin grant; the highest-risk basis, always audited as wide-scope.
     */
    WIDE_SCOPE_ADMIN,
    /**
     * The actor is the resource's owner.
     */
    RESOURCE_OWNER,
    /**
     * An organization-scoped ALLOW rule matched the actor's membership in the resource's organization.
     */
    ORGANIZATION_MEMBER,
    /**
     * A tenant-scoped ALLOW rule matched a tenant-wide role the actor holds.
     */
    EFFECTIVE_PERMISSION
}
