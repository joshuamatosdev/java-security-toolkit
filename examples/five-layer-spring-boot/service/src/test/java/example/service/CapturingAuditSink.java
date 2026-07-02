package example.service;

import io.github.joshuamatosdev.security.authz.audit.AuthorizationAuditRecord;
import io.github.joshuamatosdev.security.authz.audit.AuthorizationAuditSink;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Captures every authorization decision so the flow test can assert the audit trail — allows,
 * denies, and the wide-scope flag — alongside the HTTP outcomes. Registering it as a bean makes the
 * starter's default sink back off, exactly as an adopting application would ship its own sink.
 */
final class CapturingAuditSink implements AuthorizationAuditSink {

    private final List<AuthorizationAuditRecord> records = new CopyOnWriteArrayList<>();

    @Override
    public void record(final AuthorizationAuditRecord record) {
        records.add(record);
    }

    List<AuthorizationAuditRecord> records() {
        return List.copyOf(records);
    }

    void clear() {
        records.clear();
    }

    AuthorizationAuditRecord last() {
        if (records.isEmpty()) {
            throw new AssertionError("expected at least one audit record");
        }
        return records.getLast();
    }
}
