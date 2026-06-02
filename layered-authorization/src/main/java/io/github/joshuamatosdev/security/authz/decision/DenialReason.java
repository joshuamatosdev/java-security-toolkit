package io.github.joshuamatosdev.security.authz.decision;

/**
 * Why an access was denied — recorded in the audit trail and surfaced as the deny cause.
 */
public enum DenialReason {
    /**
     * The actor's tenant differs from the resource's tenant; the outer boundary rejected the request.
     */
    TENANT_MISMATCH,
    /**
     * A DENY rule matched the action; deny overrides any allow.
     */
    EXPLICIT_DENY,
    /**
     * No variant granted access and no rule matched — the deny-by-default outcome.
     */
    NO_MATCHING_RULE
}
