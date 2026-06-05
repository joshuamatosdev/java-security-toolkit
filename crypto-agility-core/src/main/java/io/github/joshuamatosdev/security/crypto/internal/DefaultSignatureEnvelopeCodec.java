package io.github.joshuamatosdev.security.crypto.internal;

import io.github.joshuamatosdev.security.crypto.api.SignatureEnvelopeCodec;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Default binary envelope codec used by {@code DocumentSigner}.
 *
 * <p>This class is public only so optional integrations can wire the default implementation. It is
 * not part of the stable API package.
 */
public final class DefaultSignatureEnvelopeCodec implements SignatureEnvelopeCodec {

    @Override
    public byte[] signingInput(
            final String alg,
            final String keyId,
            final byte[] publicKey,
            final byte[] payload) {
        try {
            final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            final DataOutputStream out = new DataOutputStream(bytes);
            out.writeInt(1);
            writeText(out, alg);
            writeText(out, keyId);
            writeBytes(out, publicKey, "publicKey");
            writeBytes(out, payload, "payload");
            out.flush();
            return bytes.toByteArray();
        } catch (IOException ex) {
            throw new IllegalStateException("failed to encode signed document envelope", ex);
        }
    }

    private static void writeText(final DataOutputStream out, final String value) throws IOException {
        writeBytes(out, Objects.requireNonNull(value, "value").getBytes(StandardCharsets.UTF_8), "value");
    }

    private static void writeBytes(final DataOutputStream out, final byte[] value, final String field)
            throws IOException {
        Objects.requireNonNull(value, field + " must not be null");
        out.writeInt(value.length);
        out.write(value);
    }
}
