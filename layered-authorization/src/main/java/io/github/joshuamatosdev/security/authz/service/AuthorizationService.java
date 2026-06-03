package io.github.joshuamatosdev.security.authz.service;

import io.github.joshuamatosdev.security.authz.decision.Decision;
import io.github.joshuamatosdev.security.authz.decision.DenialReason;
import io.github.joshuamatosdev.security.authz.policy.Action;
import io.github.joshuamatosdev.security.authz.principal.PolicyPrincipal;
import io.github.joshuamatosdev.security.authz.request.ProtectedResource;
import io.github.joshuamatosdev.security.authz.request.RequestContext;

import java.util.UUID;

/**
 * The policy boundary the rest of the application calls. {@link #enforce} is the deny-by-default
 * guard: it makes the decision, records it (allow or deny), and throws on a deny — so a caller that
 * forgets to check the return value still cannot proceed past a denial. {@link #decide} exposes the
 * raw outcome for callers that need to branch without throwing.
 */
public interface AuthorizationService {

    /**
     * Authorize {@code action} by {@code actor} on {@code resource}. Records an audit entry, then
     * returns normally if allowed or throws {@link AuthorizationDeniedException} if denied.
     */
    void enforce(RequestContext actor, ProtectedResource resource, Action action);

    /**
     * Make and record the decision, returning it instead of throwing.
     */
    Decision decide(RequestContext actor, ProtectedResource resource, Action action);

    /**
     * Record an already-determined boundary denial, then throw {@link AuthorizationDeniedException}.
     */
    void deny(RequestContext actor, ProtectedResource resource, Action action, DenialReason reason);

    /**
     * Record an already-determined denial without throwing. Use when the HTTP/API response is not a
     * 403, but the attempted resource access still belongs in the authorization audit trail.
     */
    void auditDeny(RequestContext actor, ProtectedResource resource, Action action, DenialReason reason);

    /**
     * Record an already-determined boundary denial before trusted tenant context exists, then throw
     * {@link AuthorizationDeniedException}.
     */
    void denyWithoutTrustedContext(
        PolicyPrincipal principal,
        UUID correlationId,
        ProtectedResource resource,
        Action action,
        DenialReason reason);
}
