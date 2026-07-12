package io.github.joshuamatosdev.security.authz.audit;

import io.github.joshuamatosdev.security.authz.decision.Allow;
import io.github.joshuamatosdev.security.authz.decision.Deny;
import io.github.joshuamatosdev.security.authz.decision.GrantBasis;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The production-style audit sink: it logs every decision, allows at INFO, and denials at WARN, with
 * the structured facts an investigation needs. A real deployment would additionally (or instead)
 * write to an append-only store; the {@link AuthorizationAuditSink} interface keeps the audit
 * destination swappable.
 *
 * <p>Why this exists: audit types capture who did what, to which resource, where, when, and why so
 * authorization can be investigated after the request.
 */
public final class Slf4jAuthorizationAuditSink implements AuthorizationAuditSink {

    private static final Logger LOG = LoggerFactory.getLogger("security.authorization.audit");

    @Override
    public void record(final AuthorizationAuditRecord record) {
        switch (record.outcome()) {
            case Allow allow -> LOG.info(
                    "authz allow basis={} wideScope={} principal={}:{} tenant={} org={} resource={} action={} corr={}",
                    allow.basis(),
                    allow.basis() == GrantBasis.WIDE_SCOPE_ADMIN,
                    record.principalType(),
                    record.principalKey(),
                    record.tenantId(),
                    record.resourceOrganizationId(),
                    record.resourceId(),
                    record.action(),
                    record.correlationId());
            case Deny deny -> LOG.warn(
                    "authz DENY reason={} principal={}:{} tenant={} org={} resource={} action={} corr={}",
                    deny.reason(),
                    record.principalType(),
                    record.principalKey(),
                    record.tenantId(),
                    record.resourceOrganizationId(),
                    record.resourceId(),
                    record.action(),
                    record.correlationId());
        }
    }
}
