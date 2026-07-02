package io.github.joshuamatosdev.security.crypto.api;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class SignatureAuditEventTest {

    @Test
    void optionalAlgorithmAndKeyIdMayBeAbsent() {
        assertThatCode(() -> new SignatureAuditEvent(
                SignatureAuditEvent.Operation.VERIFY,
                null,
                null,
                false,
                "document is null"))
            .doesNotThrowAnyException();
    }

    @Test
    void algorithmMustBeAuditSafeWhenPresent() {
        assertThatThrownBy(() -> eventWithAlgorithm(" "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("alg must not be blank");
        assertThatThrownBy(() -> eventWithAlgorithm(" EdDSA"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("alg must not include leading or trailing whitespace");
        assertThatThrownBy(() -> eventWithAlgorithm("EdDSA "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("alg must not include leading or trailing whitespace");
        assertThatThrownBy(() -> eventWithAlgorithm("EdDSA\nforged"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("alg must not contain control characters");
    }

    @Test
    void keyIdMustBeAuditSafeWhenPresent() {
        assertThatThrownBy(() -> eventWithKeyId(" "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("keyId must not be blank");
        assertThatThrownBy(() -> eventWithKeyId(" key-1"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("keyId must not include leading or trailing whitespace");
        assertThatThrownBy(() -> eventWithKeyId("key-1 "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("keyId must not include leading or trailing whitespace");
        assertThatThrownBy(() -> eventWithKeyId("key-1\nforged"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("keyId must not contain control characters");
    }

    @Test
    void reasonMustBeAuditSafeText() {
        assertThatThrownBy(() -> event(" "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("reason must not be blank");
        assertThatThrownBy(() -> event(" signed"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("reason must not include leading or trailing whitespace");
        assertThatThrownBy(() -> event("signed "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("reason must not include leading or trailing whitespace");
        assertThatThrownBy(() -> event("signed\nforged"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("reason must not contain control characters");
    }

    private static SignatureAuditEvent event(final String reason) {
        return new SignatureAuditEvent(
                SignatureAuditEvent.Operation.SIGN,
                SignatureAlgorithm.ED25519.joseAlg(),
                "key-1",
                true,
                reason);
    }

    private static SignatureAuditEvent eventWithAlgorithm(final String algorithm) {
        return new SignatureAuditEvent(
                SignatureAuditEvent.Operation.SIGN,
                algorithm,
                "key-1",
                true,
                "signed");
    }

    private static SignatureAuditEvent eventWithKeyId(final String keyId) {
        return new SignatureAuditEvent(
                SignatureAuditEvent.Operation.SIGN,
                SignatureAlgorithm.ED25519.joseAlg(),
                keyId,
                true,
                "signed");
    }
}
