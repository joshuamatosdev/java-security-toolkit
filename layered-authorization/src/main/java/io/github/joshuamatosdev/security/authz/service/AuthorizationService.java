package io.github.joshuamatosdev.security.authz.service;

import io.github.joshuamatosdev.security.authz.decision.Decision;
import io.github.joshuamatosdev.security.authz.policy.Action;
import io.github.joshuamatosdev.security.authz.request.ProtectedResource;
import io.github.joshuamatosdev.security.authz.request.RequestContext;

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
}
