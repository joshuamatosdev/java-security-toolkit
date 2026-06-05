package example;

import io.github.joshuamatosdev.security.crypto.api.DocumentSigner;
import io.github.joshuamatosdev.security.crypto.api.SignedDocument;
import java.nio.charset.StandardCharsets;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SpringBootCryptoAgilityExample {

    public static void main(final String[] args) {
        SpringApplication.run(SpringBootCryptoAgilityExample.class, args);
    }

    @Bean
    CommandLineRunner signAndVerify(final DocumentSigner signer) {
        return args -> {
            final SignedDocument signed =
                    signer.sign("workforce document".getBytes(StandardCharsets.UTF_8));
            if (!signer.verify(signed)) {
                throw new IllegalStateException("signature verification failed");
            }
            System.out.println("signed alg=" + signed.alg() + " keyId=" + signed.keyId());
        };
    }
}
