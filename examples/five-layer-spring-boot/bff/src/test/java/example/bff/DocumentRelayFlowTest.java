package example.bff;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockOidcLogin;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Proves the perimeter layers (1 and 4) of the composed example: a session-authenticated browser
 * request is relayed downstream carrying the user's access token and <em>nothing else</em> — no
 * session cookie crosses the plane boundary — while unauthenticated and CSRF-less requests are
 * refused at the door, before any downstream call.
 *
 * <p>The downstream double stands in for the {@code service} subproject; its own test proves what
 * happens on the other side of this hop with the same claims contract.
 */
@SpringBootTest
@AutoConfigureWebTestClient
class DocumentRelayFlowTest {

    /**
     * The access-token value spring-security-test's {@code mockOidcLogin()} places in the
     * session's authorized client — the token the relay must forward.
     */
    private static final String MUTATOR_ACCESS_TOKEN = "access-token";

    /**
     * Mirrors the {@code idp} registration in {@code application.yaml} so the mutator's authorized
     * client is stored under the registration id {@link DocumentRelayController} resolves.
     */
    private static final ClientRegistration IDP_REGISTRATION = ClientRegistration
            .withRegistrationId("idp")
            .clientId("five-layer-bff")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/login/oauth2/code/idp")
            .scope("openid")
            .authorizationUri("https://idp.acme.example/oauth2/authorize")
            .tokenUri("https://idp.acme.example/oauth2/token")
            .jwkSetUri("https://idp.acme.example/oauth2/jwks")
            .userNameAttributeName("sub")
            .build();

    private static final MockWebServer DOWNSTREAM = new MockWebServer();

    static {
        try {
            DOWNSTREAM.start();
        } catch (final IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @DynamicPropertySource
    static void props(final DynamicPropertyRegistry registry) {
        registry.add("downstream.service-base-url", () -> DOWNSTREAM.url("/").toString());
    }

    @AfterAll
    static void stopDownstream() throws IOException {
        DOWNSTREAM.shutdown();
    }

    @Autowired
    private WebTestClient client;

    @BeforeEach
    void drainDownstream() throws InterruptedException {
        // The server is shared; drop anything a previous test left so takeRequest is per-test.
        while (DOWNSTREAM.takeRequest(10, TimeUnit.MILLISECONDS) != null) {
            // drain
        }
    }

    private WebTestClient authenticated() {
        return client.mutateWith(mockOidcLogin().clientRegistration(IDP_REGISTRATION));
    }

    private static RecordedRequest relayedRequest() throws InterruptedException {
        final RecordedRequest relayed = DOWNSTREAM.takeRequest(5, TimeUnit.SECONDS);
        assertThat(relayed).isNotNull();
        return relayed;
    }

    private static void assertNothingWasRelayed() throws InterruptedException {
        assertThat(DOWNSTREAM.takeRequest(300, TimeUnit.MILLISECONDS)).isNull();
    }

    @Test
    void relaysTheUsersAccessTokenAndNeverTheSessionCookie() throws Exception {
        DOWNSTREAM.enqueue(new MockResponse()
                .setHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .setBody("[]"));

        authenticated().get().uri("/api/documents").exchange().expectStatus().isOk();

        final RecordedRequest relayed = relayedRequest();
        assertThat(relayed.getPath()).isEqualTo("/documents");
        // The plane swap: bearer token out, browser credentials stay home.
        assertThat(relayed.getHeader(HttpHeaders.AUTHORIZATION))
                .isEqualTo("Bearer " + MUTATOR_ACCESS_TOKEN);
        assertThat(relayed.getHeader(HttpHeaders.COOKIE)).isNull();
    }

    @Test
    void refusesAnonymousBrowsersAtThePerimeterWithoutTouchingDownstream() throws Exception {
        client.get().uri("/api/documents").exchange().expectStatus().is3xxRedirection();

        assertNothingWasRelayed();
    }

    @Test
    void refusesAWriteWithoutTheCsrfEchoBeforeAnyRelay() throws Exception {
        // Session-authenticated but no X-XSRF-TOKEN double-submit echo: layer 4 refuses the write
        // at the perimeter; the downstream service never hears about it.
        authenticated()
                .post()
                .uri("/api/documents")
                .bodyValue("{\"title\":\"t\",\"body\":\"b\"}")
                .exchange()
                .expectStatus().isForbidden();

        assertNothingWasRelayed();
    }

    @Test
    void relaysAWriteThatPresentsTheCsrfEcho() throws Exception {
        DOWNSTREAM.enqueue(new MockResponse()
                .setHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .setBody("{\"id\":\"fictional\"}"));

        authenticated()
                .mutateWith(csrf())
                .post()
                .uri("/api/documents")
                .bodyValue("{\"title\":\"launch plan\",\"body\":\"fictional\"}")
                .exchange()
                .expectStatus().isOk();

        final RecordedRequest relayed = relayedRequest();
        assertThat(relayed.getPath()).isEqualTo("/documents");
        assertThat(relayed.getHeader(HttpHeaders.AUTHORIZATION))
                .isEqualTo("Bearer " + MUTATOR_ACCESS_TOKEN);
    }
}
