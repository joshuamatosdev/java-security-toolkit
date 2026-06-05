package io.github.joshuamatosdev.security.crypto.api;

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
        operation = Objects.requireNonNull(operation, "operation must not be null");
        reason = requireAuditText(reason, "reason");
    }

    private static String requireAuditText(final String value, final String field) {
        Objects.requireNonNull(value, field + " must not be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        if (!value.equals(value.strip())) {
            throw new IllegalArgumentException(field + " must not include leading or trailing whitespace");
        }
        if (value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(field + " must not contain control characters");
        }
        return value;
    }
}
