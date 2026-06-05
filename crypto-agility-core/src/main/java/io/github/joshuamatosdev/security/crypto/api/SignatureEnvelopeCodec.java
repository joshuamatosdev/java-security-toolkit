package io.github.joshuamatosdev.security.crypto.api;

/**
 * Encodes the bytes that are actually signed and verified for a document envelope.
 *
 * <p>The default codec signs algorithm id, key id, public key, and payload. Custom codecs let
 * adopters align this library with a protocol-specific envelope without changing providers.
 */
@FunctionalInterface
public interface SignatureEnvelopeCodec {

    /** Returns the canonical signing input for the supplied envelope fields. */
    byte[] signingInput(String alg, String keyId, byte[] publicKey, byte[] payload);
}
