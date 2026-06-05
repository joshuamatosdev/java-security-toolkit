package io.github.joshuamatosdev.security.crypto.api;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class SignatureAuditEventTest {

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
}
