package io.github.joshuamatosdev.security.crypto.seal;

import io.github.joshuamatosdev.security.crypto.key.KeyHandle;
import io.github.joshuamatosdev.security.crypto.registry.SignatureAlgorithm;
import io.github.joshuamatosdev.security.crypto.registry.SignatureProviderRegistry;

/**
 * The agility property, demonstrated. This is the call site: it seals a document with a key and
 * verifies a sealed document, and <b>it names no algorithm</b>.
 *
 * <p>{@link #seal} reads the algorithm off the {@link KeyHandle}; {@link #verify} resolves the
 * provider off the document's {@code alg} label through the registry. Swapping a deployment from
 * Ed25519 to ECDSA P-256 to the post-quantum slot changes only which {@link KeyHandle} is handed in
 * — the bytecode of these two methods is identical across every algorithm. That is what
 * cryptographic agility means in practice: the policy decision (which algorithm) is data, not code.
 */
public final class DocumentSigner {

    private final SignatureProviderRegistry registry;

    public DocumentSigner(final SignatureProviderRegistry registry) {
        this.registry = registry;
    }

    /**
     * Seals a document by signing it with the given key.
     *
     * @param key the signing key handle
     * @param document the bytes to seal
     * @return the document, its signature, and the metadata needed to verify it
     */
    public SignedDocument seal(final KeyHandle key, final byte[] document) {
        final byte[] signature = key.sign(document);
        return new SignedDocument(
                key.algorithm().joseAlg(), key.keyId(), key.publicKey(), document, signature);
    }

    /**
     * Verifies a sealed document.
     *
     * @param document the sealed document
     * @return {@code true} iff its signature is valid under its declared algorithm and key
     */
    public boolean verify(final SignedDocument document) {
        final SignatureAlgorithm algorithm = SignatureAlgorithm.fromJoseAlg(document.alg());
        return registry
                .resolve(algorithm)
                .verify(document.publicKey(), document.payload(), document.signature());
    }
}
