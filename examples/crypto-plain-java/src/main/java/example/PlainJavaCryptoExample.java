package example;

import io.github.joshuamatosdev.security.crypto.api.DocumentSigner;
import io.github.joshuamatosdev.security.crypto.api.KeyHandle;
import io.github.joshuamatosdev.security.crypto.api.SignatureAlgorithm;
import io.github.joshuamatosdev.security.crypto.api.SignatureProviderRegistry;
import io.github.joshuamatosdev.security.crypto.api.SignedDocument;
import io.github.joshuamatosdev.security.crypto.jca.JcaSignatureProviders;
import java.nio.charset.StandardCharsets;
import java.util.List;

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
        if (!signer.verify(signed)) {
            throw new IllegalStateException("signature verification failed");
        }

        System.out.println("signed alg=" + signed.alg() + " keyId=" + signed.keyId());
    }
}
