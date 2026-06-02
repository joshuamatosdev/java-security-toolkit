package io.github.joshuamatosdev.security.authz.testfixtures;

import io.github.joshuamatosdev.security.authz.audit.AuthorizationAuditRecord;
import io.github.joshuamatosdev.security.authz.audit.AuthorizationAuditSink;

import java.util.ArrayList;
import java.util.List;

/**
 * A test double for the {@link AuthorizationAuditSink} port that captures every record, so a test can
 * assert that a decision — in particular a denial — was written before the guard threw. This is a
 * fake of a <em>secondary</em> port (the audit destination), not of the system under test.
 */
public final class CapturingAuditSink implements AuthorizationAuditSink {

    private final List<AuthorizationAuditRecord> records = new ArrayList<>();

    @Override
    public void record(final AuthorizationAuditRecord record) {
        records.add(record);
    }

    public List<AuthorizationAuditRecord> records() {
        return List.copyOf(records);
    }

    public AuthorizationAuditRecord only() {
        if (records.size() != 1) {
            throw new AssertionError("expected exactly one audit record but captured " + records.size());
        }
        return records.get(0);
    }
}
