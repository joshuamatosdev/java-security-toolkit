package io.github.joshuamatosdev.security.edge.chain;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Proves the service plane enforces the issuer and audience boundary on a REAL signed bearer token,
 * through the real resource-server decoder. This closes a coverage gap: {@code
 * ServiceApiAuthorizationTest} drives the plane with {@code mockJwt()}, which injects a
 * pre-authenticated token and never runs the decoder, so it can prove role-gating but not that the
 * {@code iss}/{@code aud} checks actually execute.
 *
 * <p>The enforcement is wired indirectly: {@code ServiceApiSecurityChainConfig} publishes
 * {@code serviceJwtBoundaryValidator} as a plain {@code OAuth2TokenValidator<Jwt>} bean, and Spring
 * Boot's reactive resource-server auto-configuration composes every such bean into the decoder's
 * validator chain (see {@code ReactiveOAuth2ResourceServerJwkConfiguration}, which collects them via
 * {@code ObjectProvider<OAuth2TokenValidator<Jwt>>} and {@code DelegatingOAuth2TokenValidator}). That
 * mechanism is not described in the Spring Security reference, so this test pins it: if a framework
 * upgrade or a refactor ever stopped composing the bean, the rejections below would turn into 200s.
 *
 * <p>An in-process {@link MockWebServer} serves the JWK set the decoder fetches; tokens are signed
 * with the matching key so the signature is genuinely valid and the only variable under test is the
 * {@code iss} / {@code aud} claim.
 *
 * <p>Why this is important to test: browser sessions and service JWTs are separate credential
 * planes, and validator drift could accept the wrong token.
 */
@SpringBootTest
@AutoConfigureWebTestClient
class ServiceJwtValidationTest {

  private static final String TRUSTED_ISSUER = "https://idp.acme.example";
  private static final String ACCEPTED_AUDIENCE = "edge-service-api";
  private static final String KEY_ID = "service-test-key";

  private static MockWebServer jwksServer;
  private static RSAKey signingKey;

  @Autowired private WebTestClient webClient;

  @BeforeAll
  static void startJwksServer() throws Exception {
    signingKey = new RSAKeyGenerator(2048).keyID(KEY_ID).generate();
    final String jwks = new JWKSet(signingKey.toPublicJWK()).toString();
    jwksServer = new MockWebServer();
    jwksServer.setDispatcher(
        new Dispatcher() {
          @Override
          public MockResponse dispatch(RecordedRequest request) {
            return new MockResponse()
                .setResponseCode(200)
                .addHeader("Content-Type", "application/json")
                .setBody(jwks);
          }
        });
    jwksServer.start();
  }

  @AfterAll
  static void stopJwksServer() throws Exception {
    jwksServer.shutdown();
  }

  @DynamicPropertySource
  static void resourceServerJwks(DynamicPropertyRegistry registry) {
    // Point the resource-server decoder at the in-process JWKS so signature verification succeeds
    // for our test-signed tokens; the issuer/audience checks are what the assertions probe.
    registry.add(
        "spring.security.oauth2.resourceserver.jwt.jwk-set-uri",
        () -> jwksServer.url("/jwks").toString());
    registry.add("edge.identity.issuer-uri", () -> TRUSTED_ISSUER);
  }

  private String signedServiceToken(String issuer, String audience) throws Exception {
    final Instant now = Instant.now();
    final JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .issuer(issuer)
            .audience(audience)
            .subject("service-client")
            .claim("roles", List.of("service"))
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(300)))
            .build();
    final SignedJWT jwt =
        new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(KEY_ID)
                .type(JOSEObjectType.JWT)
                .build(),
            claims);
    jwt.sign(new RSASSASigner(signingKey));
    return jwt.serialize();
  }

  @Test
  void rejectsServiceTokenSignedByTheTrustedKeyButCarryingTheWrongIssuer() throws Exception {
    webClient
        .get()
        .uri("/api/service/reports")
        .header(
            HttpHeaders.AUTHORIZATION,
            "Bearer " + signedServiceToken("https://evil.example", ACCEPTED_AUDIENCE))
        .exchange()
        .expectStatus()
        .isUnauthorized();
  }

  @Test
  void rejectsServiceTokenSignedByTheTrustedKeyButCarryingTheWrongAudience() throws Exception {
    webClient
        .get()
        .uri("/api/service/reports")
        .header(
            HttpHeaders.AUTHORIZATION,
            "Bearer " + signedServiceToken(TRUSTED_ISSUER, "some-other-resource"))
        .exchange()
        .expectStatus()
        .isUnauthorized();
  }

  /**
   * Positive control: a token signed by the trusted key, with the trusted issuer, an accepted
   * audience, and {@code roles:[service]} must reach the handler (200). If this fails, the harness
   * (JWKS fetch / signature) is broken and the rejection assertions above are meaningless.
   */
  @Test
  void acceptsCorrectlyIssuedAndAudiencedServiceToken() throws Exception {
    webClient
        .get()
        .uri("/api/service/reports")
        .header(
            HttpHeaders.AUTHORIZATION,
            "Bearer " + signedServiceToken(TRUSTED_ISSUER, ACCEPTED_AUDIENCE))
        .exchange()
        .expectStatus()
        .isOk();
  }
}
