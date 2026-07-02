package example;

import io.github.joshuamatosdev.security.crypto.api.DocumentSigner;
import io.github.joshuamatosdev.security.crypto.api.KeyHandle;
import io.github.joshuamatosdev.security.crypto.api.KeyHandleResolver;
import io.github.joshuamatosdev.security.crypto.api.SignedDocument;
import io.github.joshuamatosdev.security.crypto.api.TrustAnchor;
import io.github.joshuamatosdev.security.crypto.spring.CryptoProperties;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SpringBootCryptoExample {

    public static void main(final String[] args) {
        SpringApplication.run(SpringBootCryptoExample.class, args);
    }

    @Bean
    CommandLineRunner signAndVerify(
            final DocumentSigner signer,
            final KeyHandleResolver keys,
            final CryptoProperties properties) {
        return args -> {
            final SignedDocument signed =
                    signer.sign("workforce document".getBytes(StandardCharsets.UTF_8));

            // Integrity: the key embedded in the document verifies the payload.
            if (!signer.verify(signed)) {
                throw new IllegalStateException("signature verification failed");
            }

            // Authenticity: pin the deployment's own key material for the default key id — the
            // wiring's opinion of the trusted key, never the key embedded in the document under
            // test. A tampered payload re-signed with an attacker's key then fails closed.
            final KeyHandle trusted =
                    keys.resolve(properties.defaultAlgorithm(), properties.defaultKeyId());
            final TrustAnchor anchor =
                    TrustAnchor.pinnedKeys(Map.of(trusted.keyId(), trusted.publicKey()));
            if (!signer.verify(signed, anchor)) {
                throw new IllegalStateException("trust-anchored verification failed");
            }

            System.out.println("signed alg=" + signed.alg() + " keyId=" + signed.keyId()
                    + " trustAnchored=true");
        };
    }
}
