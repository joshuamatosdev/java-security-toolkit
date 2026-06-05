package io.github.joshuamatosdev.security.authz.principal;

/**
 * Whether the actor is a human user or a machine (service) caller.
 *
 * <p>Why this exists: typed principals keep human users and service clients distinct before route
 * gates or resource policies make decisions.
 */
public enum PrincipalType {
    USER,
    SERVICE
}
