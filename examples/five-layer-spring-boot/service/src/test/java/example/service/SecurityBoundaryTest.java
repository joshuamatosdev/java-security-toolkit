package example.service;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.github.joshuamatosdev.security.tenant.binding.TenantContext;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@WebMvcTest(controllers = SecurityBoundaryTest.ProbeController.class)
@Import({SecurityConfig.class, SecurityBoundaryTest.BoundaryTestConfiguration.class})
class SecurityBoundaryTest {

    private static final String ISSUER = "https://idp.acme.example";
    private static final String EXPECTED_AUDIENCE = "edge-service-api";
    private static final String VALID_TENANT = "0190a000-0000-7000-8000-0000000000a1";
    private static final KeyPair KEY_PAIR = generateKeyPair();
    private static final Path PUBLIC_KEY_FILE = writePublicKey();

    @DynamicPropertySource
    static void jwtProperties(final DynamicPropertyRegistry registry) {
        registry.add("JWT_AUDIENCE", () -> EXPECTED_AUDIENCE);
        registry.add(
                "spring.security.oauth2.resourceserver.jwt.public-key-location",
                () -> PUBLIC_KEY_FILE.toUri().toString());
    }

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ProbeController probe;

    @BeforeEach
    void resetProbe() {
        probe.reset();
    }

    @AfterAll
    static void deletePublicKey() throws IOException {
        Files.deleteIfExists(PUBLIC_KEY_FILE);
    }

    @Test
    void tokenForAnotherAudienceIsRejectedBeforeTheController() throws Exception {
        mvc.perform(get("/documents")
                        .header(AUTHORIZATION, "Bearer " + token("another-api", VALID_TENANT)))
                .andExpect(status().isUnauthorized());

        assertThat(probe.invocations()).isZero();
    }

    @Test
    void tokenForTheConfiguredAudienceReachesTheController() throws Exception {
        mvc.perform(get("/documents")
                        .header(AUTHORIZATION, "Bearer " + token(EXPECTED_AUDIENCE, VALID_TENANT)))
                .andExpect(status().isOk());

        assertThat(probe.invocations()).isOne();
    }

    private static String token(final String audience, final String tenant) throws Exception {
        final Instant now = Instant.now();
        final JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject("alice")
                .audience(audience)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .claim("tenant_id", tenant)
                .claim("roles", List.of("MEMBER"));
        final SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(),
                claims.build());
        jwt.sign(new RSASSASigner((RSAPrivateKey) KEY_PAIR.getPrivate()));
        return jwt.serialize();
    }

    private static KeyPair generateKeyPair() {
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException("could not generate test RSA key", ex);
        }
    }

    private static Path writePublicKey() {
        try {
            final String encoded = Base64.getMimeEncoder(64, "\n".getBytes(UTF_8))
                    .encodeToString(KEY_PAIR.getPublic().getEncoded());
            final Path file = Files.createTempFile("five-layer-public-key-", ".pem");
            Files.writeString(
                    file,
                    "-----BEGIN PUBLIC KEY-----\n" + encoded + "\n-----END PUBLIC KEY-----\n",
                    UTF_8);
            return file;
        } catch (IOException ex) {
            throw new IllegalStateException("could not write test RSA public key", ex);
        }
    }

    @RestController
    static class ProbeController {
        private final AtomicInteger invocations = new AtomicInteger();

        @GetMapping("/documents")
        String probe() {
            invocations.incrementAndGet();
            return "ok";
        }

        int invocations() {
            return invocations.get();
        }

        void reset() {
            invocations.set(0);
        }
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class BoundaryTestConfiguration {
        @Bean
        TenantContext tenantContext() {
            return new TenantContext(() -> false);
        }

        @Bean
        ProbeController probeController() {
            return new ProbeController();
        }
    }
}
