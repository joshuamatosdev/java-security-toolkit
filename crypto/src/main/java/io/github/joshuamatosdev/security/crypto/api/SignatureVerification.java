package io.github.joshuamatosdev.security.crypto.api;

import java.util.Objects;

/** Typed result of document signature verification. */
public sealed interface SignatureVerification
        permits SignatureVerification.Verified, SignatureVerification.Rejected {

    /** True only for a successfully verified signature. */
    default boolean isVerified() {
        return this instanceof Verified;
    }

    /** Successful verification. */
    record Verified() implements SignatureVerification {}

    /** Failed verification with a stable, machine-readable reason. */
    record Rejected(Failure failure) implements SignatureVerification {
        public Rejected {
            Objects.requireNonNull(failure, "failure must not be null");
        }
    }

    /** Expected fail-closed verification outcomes. */
    enum Failure {
        DOCUMENT_MISSING("document is null"),
        PROVIDER_MISSING("provider missing"),
        INVALID_SIGNATURE("verification failed"),
        UNTRUSTED_KEY("untrusted key");

        private final String auditReason;

        Failure(final String auditReason) {
            this.auditReason = auditReason;
        }

        public String auditReason() {
            return auditReason;
        }
    }

    static SignatureVerification verified() {
        return new Verified();
    }

    static SignatureVerification rejected(final Failure failure) {
        return new Rejected(failure);
    }
}
