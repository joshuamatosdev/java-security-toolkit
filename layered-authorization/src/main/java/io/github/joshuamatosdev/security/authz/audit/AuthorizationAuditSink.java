package io.github.joshuamatosdev.security.authz.audit;

/**
 * Where decisions are recorded. A port (seam) so the audit destination — a log, an append-only
 * table, an event stream — is an adapter detail, and so tests can capture decisions and assert that
 * a denial was logged. A denial that is not recorded did not happen, as far as an audit is concerned.
 */
public interface AuthorizationAuditSink {

    void record(AuthorizationAuditRecord record);
}
