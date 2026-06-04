package io.github.joshuamatosdev.security.edge.csrf;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestHandler;
import org.springframework.security.web.server.csrf.XorServerCsrfTokenRequestAttributeHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Masks the response-visible CSRF token while preserving the SPA double-submit contract.
 *
 * <p>{@link XorServerCsrfTokenRequestAttributeHandler} protects response-rendered token values from
 * BREACH-style compression disclosure by XOR-masking each render with a fresh random pad. The SPA,
 * however, reads the host-only {@code XSRF-TOKEN} cookie and echoes that <em>raw</em> value back in
 * the {@code X-XSRF-TOKEN} header. So token resolution tries the XOR path first (the masked value a
 * compliant client computed), then falls back to accepting the raw cookie value — but only when it
 * constant-time matches the repository token. Response attributes stay XOR-masked either way.
 */
public final class SpaCompatibleXorServerCsrfTokenRequestHandler
    implements ServerCsrfTokenRequestHandler {

  private final XorServerCsrfTokenRequestAttributeHandler xorHandler =
      new XorServerCsrfTokenRequestAttributeHandler();
  private final ServerCsrfTokenRequestAttributeHandler rawHeaderHandler =
      new ServerCsrfTokenRequestAttributeHandler();

  @Override
  public void handle(ServerWebExchange exchange, Mono<CsrfToken> csrfToken) {
    xorHandler.handle(exchange, csrfToken);
  }

  @Override
  public Mono<String> resolveCsrfTokenValue(ServerWebExchange exchange, CsrfToken csrfToken) {
    return xorHandler
        .resolveCsrfTokenValue(exchange, csrfToken)
        .switchIfEmpty(
            rawHeaderHandler
                .resolveCsrfTokenValue(exchange, csrfToken)
                .filter(candidate -> constantTimeEquals(candidate, csrfToken.getToken())));
  }

  private static boolean constantTimeEquals(String candidate, String expected) {
    return MessageDigest.isEqual(
        candidate.getBytes(StandardCharsets.UTF_8), expected.getBytes(StandardCharsets.UTF_8));
  }
}
