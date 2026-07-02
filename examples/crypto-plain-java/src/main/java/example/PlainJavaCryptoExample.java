package example;

import io.github.joshuamatosdev.security.crypto.api.DocumentSigner;
import io.github.joshuamatosdev.security.crypto.api.KeyHandle;
import io.github.joshuamatosdev.security.crypto.api.SignatureAlgorithm;
import io.github.joshuamatosdev.security.crypto.api.SignatureProviderRegistry;
import io.github.joshuamatosdev.security.crypto.api.SignedDocument;
import io.github.joshuamatosdev.security.crypto.api.TrustAnchor;
import io.github.joshuamatosdev.security.crypto.jca.JcaSignatureProviders;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

public final class PlainJavaCryptoExample {

    private PlainJavaCryptoExample() {
    }

    public static void main(final String[] args) {
        final SignatureProviderRegistry registry =
                new SignatureProviderRegistry(List.of(JcaSignatureProviders.ed25519()));
        final DocumentSigner signer = new DocumentSigner(registry);
        final KeyHandle key = registry.resolve(SignatureAlgorithm.ED25519).generateKey("local-ed25519-1");

        final SignedDocument signed =
                signer.sign(key, "workforce document".getBytes(StandardCharsets.UTF_8));

        // Integrity: the key embedded in the document verifies the payload.
        if (!signer.verify(signed)) {
            throw new IllegalStateException("signature verification failed");
        }

        // Authenticity: the verifier pins its own opinion of which key may speak for the key id,
        // so a tampered payload re-signed with an attacker's embedded key fails closed. Pin from
        // your key custody or configuration — never from the document you are verifying.
        final TrustAnchor anchor = TrustAnchor.pinnedKeys(Map.of(key.keyId(), key.publicKey()));
        if (!signer.verify(signed, anchor)) {
            throw new IllegalStateException("trust-anchored verification failed");
        }

        System.out.println("signed alg=" + signed.alg() + " keyId=" + signed.keyId()
                + " trustAnchored=true");
    }
}
