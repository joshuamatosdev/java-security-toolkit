package io.github.joshuamatosdev.security.crypto.seal;

import io.github.joshuamatosdev.security.crypto.key.KeyHandle;
import io.github.joshuamatosdev.security.crypto.provider.SignatureProvider;
import io.github.joshuamatosdev.security.crypto.registry.SignatureAlgorithm;
import io.github.joshuamatosdev.security.crypto.registry.SignatureProviderRegistry;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * The agility property, demonstrated. This is the call site: it seals a document with a key and
 * verifies a sealed document, and <b>it names no algorithm</b>.
 *
 * <p>{@link #seal} reads the algorithm off the {@link KeyHandle}; {@link #verify} resolves the
 * provider off the document's {@code alg} label through the registry. Swapping a deployment from
 * Ed25519 to ECDSA P-256 to the post-quantum slot changes only which {@link KeyHandle} is handed in
 * — the bytecode of these two methods is identical across every algorithm. That is what
 * cryptographic agility means in practice: the policy decision (which algorithm) is data, not code.
 *
 * <p>Why this exists: document sealing is the stable call site that proves signature algorithms
 * can be swapped behind the same interface.
 */
public final class DocumentSigner {

    private final SignatureProviderRegistry registry;

    public DocumentSigner(final SignatureProviderRegistry registry) {
        this.registry = Objects.requireNonNull(registry, "registry must not be null");
    }

    /**
     * Seals a document by signing it with the given key.
     *
     * @param key the signing key handle
     * @param document the bytes to seal
     * @return the document, its signature, and the metadata needed to verify it
     */
    public SignedDocument seal(final KeyHandle key, final byte[] document) {
        Objects.requireNonNull(key, "key must not be null");
        Objects.requireNonNull(document, "document must not be null");

        final String alg = key.algorithm().joseAlg();
        final String keyId = key.keyId();
        final byte[] publicKey = key.publicKey();
        final byte[] signature = key.sign(signingInput(alg, keyId, publicKey, document));
        return new SignedDocument(alg, keyId, publicKey, document, signature);
    }

    /**
     * Verifies a sealed document against the public key carried inside the document itself.
     *
     * <p><b>Integrity, not authenticity.</b> A {@code true} result proves the payload was not
     * altered after it was signed by whoever holds the private key matching
     * {@link SignedDocument#publicKey()} — it does <em>not</em> prove that key belongs to a trusted
     * signer. Because the verifying key travels inside the document, an attacker can re-sign
     * arbitrary content under their own key pair and embed their own public key (the JWK-injection
     * pattern) and still pass. A caller that needs authenticity must check
     * {@link SignedDocument#publicKey()} against a trust anchor — an allow-list of known keys or a
     * certificate chain — before trusting the payload.
     *
     * @param document the sealed document
     * @return {@code true} iff its signature is valid under its declared algorithm and embedded key
     */
    public boolean verify(final SignedDocument document) {
        if (document == null) {
            return false;
        }
        final SignatureProvider provider;
        try {
            final SignatureAlgorithm algorithm = SignatureAlgorithm.fromJoseAlg(document.alg());
            provider = registry.resolve(algorithm);
        } catch (IllegalArgumentException ex) {
            return false;
        }
        final byte[] publicKey = document.publicKey();
        return provider.verify(
                publicKey,
                signingInput(document.alg(), document.keyId(), publicKey, document.payload()),
                document.signature());
    }

    private static byte[] signingInput(
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
