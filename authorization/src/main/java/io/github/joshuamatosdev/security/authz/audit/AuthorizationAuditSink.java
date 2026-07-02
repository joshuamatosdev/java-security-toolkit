package io.github.joshuamatosdev.security.authz.audit;

/**
 * Where decisions are recorded. This interface keeps the audit destination — a log, an append-only
 * table, an event stream — as an adapter detail, and lets tests capture decisions and assert that a
 * denial was logged. A denial that is not recorded did not happen, as far as an audit is concerned.
 *
 * <p>Why this exists: audit types capture who did what, to which resource, where, when, and why so
 * authorization can be investigated after the request.
 */
public interface AuthorizationAuditSink {

    void record(AuthorizationAuditRecord record);
}
