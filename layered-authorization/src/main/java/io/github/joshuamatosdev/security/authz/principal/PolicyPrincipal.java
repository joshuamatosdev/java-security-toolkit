package io.github.joshuamatosdev.security.authz.principal;

/**
 * The authenticated actor an authorization decision is made <em>about</em>. Sealed to a closed set
 * — exactly a {@link UserPrincipal} (a human) or a {@link ServicePrincipal} (a machine caller) — so
 * that a raw {@code String} subject or an untyped claims map can never stand in for an actor, and so
 * the compiler forces every decision site to handle both kinds.
 *
 * <p>Why this exists: typed principals keep human users and service clients distinct before route
 * gates or resource policies make decisions.
 */
public sealed interface PolicyPrincipal permits UserPrincipal, ServicePrincipal {

    PrincipalType principalType();

    /**
     * Stable identity key: the subject for a user, the client id for a service.
     */
    String principalKey();

    /**
     * Monotonic version of the actor's authorization facts. Bumped when a grant changes so a cached
     * decision keyed on an old version is forced to re-evaluate rather than serve a stale allow.
     */
    long authorizationVersion();
}
