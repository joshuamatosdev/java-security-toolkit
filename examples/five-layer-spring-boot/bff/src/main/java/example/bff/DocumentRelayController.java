package example.bff;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * The BFF token relay — the only downstream code this application owns.
 *
 * <p>The browser plane admitted this request with a <em>session cookie</em>; the session's OAuth2
 * authorized client holds the user's access token from the login. The relay swaps credential
 * planes explicitly: it builds a fresh downstream request carrying only that bearer token — the
 * session cookie, CSRF echo, and any other browser credential never leave this process. That is
 * the browser/service plane separation made concrete: the cookie is a perimeter credential, the
 * token is the cross-service identity statement.
 *
 * <p>The routes sit under the browser plane's authenticated document surface
 * (the document entries in {@code BrowserRouteTable}); the downstream service re-verifies the token against
 * the same pinned issuer and makes its own authorization and tenant-isolation decisions — the
 * perimeter's word is never authority past the perimeter.
 */
@RestController
public class DocumentRelayController {

    private final WebClient downstream;

    public DocumentRelayController(
            final WebClient.Builder webClientBuilder,
            @Value("${downstream.service-base-url}") final String serviceBaseUrl) {
        this.downstream = webClientBuilder.baseUrl(serviceBaseUrl).build();
    }

    @GetMapping("/api/documents")
    public Mono<String> list(
            @RegisteredOAuth2AuthorizedClient("idp") final OAuth2AuthorizedClient client) {
        return downstream.get()
                .uri("/documents")
                .headers(headers -> headers.setBearerAuth(client.getAccessToken().getTokenValue()))
                .retrieve()
                .bodyToMono(String.class);
    }

    @PostMapping("/api/documents")
    public Mono<String> create(
            @RegisteredOAuth2AuthorizedClient("idp") final OAuth2AuthorizedClient client,
            @RequestBody final String body) {
        return downstream.post()
                .uri("/documents")
                .contentType(MediaType.APPLICATION_JSON)
                .headers(headers -> headers.setBearerAuth(client.getAccessToken().getTokenValue()))
                .bodyValue(body)
                .retrieve()
                .bodyToMono(String.class);
    }
}
