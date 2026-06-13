package io.github.joshuamatosdev.security.crypto.api;

/**
 * Receives signing and verification audit events.
 *
 * <p>The core library defaults to a no-op sink. Production applications should connect this to an
 * immutable audit/event pipeline when signature activity is security relevant.
 */
@FunctionalInterface
public interface SignatureAuditSink {

    /** Records one event. Implementations should avoid throwing for normal audit transport issues. */
    void record(SignatureAuditEvent event);

    /** No-op audit sink for applications that do not need audit events from this library. */
    static SignatureAuditSink noop() {
        return event -> { };
    }
}
