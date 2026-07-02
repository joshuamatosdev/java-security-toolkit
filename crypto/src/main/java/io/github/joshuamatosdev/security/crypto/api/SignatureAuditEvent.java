package io.github.joshuamatosdev.security.crypto.api;

import io.github.joshuamatosdev.security.shared.RequiredText;
import java.util.Objects;

/** Audit event emitted by {@link DocumentSigner}. */
public record SignatureAuditEvent(
        Operation operation,
        String alg,
        String keyId,
        boolean success,
        String reason) {

    /** Signing lifecycle operation. */
    public enum Operation {
        SIGN,
        VERIFY
    }

    public SignatureAuditEvent {
        Objects.requireNonNull(operation, "operation must not be null");
        alg = requireOptionalAuditText(alg, "alg");
        keyId = requireOptionalAuditText(keyId, "keyId");
        reason = requireAuditText(reason, "reason");
    }

    private static String requireOptionalAuditText(final String value, final String field) {
        return value == null ? null : requireAuditText(value, field);
    }

    private static String requireAuditText(final String value, final String field) {
        return RequiredText.require(value, field);
    }
}
