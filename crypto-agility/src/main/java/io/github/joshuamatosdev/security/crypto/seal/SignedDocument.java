package io.github.joshuamatosdev.security.crypto.seal;

/**
 * A document together with the signature over it and everything a verifier needs to check it: the
 * {@code alg} wire identifier, the versioned key id, and the encoded public key.
 *
 * <p>The {@code alg} field is what makes verification algorithm-agnostic — a verifier reads it,
 * resolves the matching provider from the registry, and checks the signature, without the call site
 * naming any algorithm. The byte-array components are defensively copied on the way in and out so an
 * instance is genuinely immutable.
 *
 * @param alg the JOSE {@code alg} header value the document was signed under
 * @param keyId the versioned identifier of the signing key
 * @param publicKey the encoded public key to verify against
 * @param payload the signed document bytes
 * @param signature the signature bytes
 */
public record SignedDocument(
        String alg, String keyId, byte[] publicKey, byte[] payload, byte[] signature) {

    public SignedDocument {
        publicKey = publicKey.clone();
        payload = payload.clone();
        signature = signature.clone();
    }

    @Override
    public byte[] publicKey() {
        return publicKey.clone();
    }

    @Override
    public byte[] payload() {
        return payload.clone();
    }

    @Override
    public byte[] signature() {
        return signature.clone();
    }
}
