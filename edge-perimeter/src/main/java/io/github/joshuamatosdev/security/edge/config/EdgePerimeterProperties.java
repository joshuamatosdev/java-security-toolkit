package io.github.joshuamatosdev.security.edge.config;

import java.net.URI;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

/**
 * Deployment-shape knobs for the edge perimeter. Everything here is environment policy — which
 * origins may script against the BFF, whether cookies require TLS, whether HSTS is emitted
 * unconditionally — and nothing here weakens the perimeter's structural rules (deny-by-default
 * route map, plane separation), which are code, not configuration.
 *
 * @param cors browser origins allowed to make credentialed cross-origin requests
 * @param cookie cookie transport policy
 * @param hsts Strict-Transport-Security emission policy
 * @param identity trusted identity-provider issuer
 * @param serviceJwt service-plane JWT boundary
 *
 * <p>Why this exists: CORS and cookie policy are credentialed browser trust decisions, so their
 * allow-lists need to be explicit and auditable.
 */
@ConfigurationProperties(prefix = "edge")
public record EdgePerimeterProperties(
    Cors cors, Cookie cookie, Hsts hsts, Identity identity, ServiceJwt serviceJwt) {

  public static final String DEFAULT_ISSUER_URI = "https://idp.acme.example";
  public static final String DEFAULT_SERVICE_AUDIENCE = "edge-service-api";

  public EdgePerimeterProperties(Cors cors, Cookie cookie, Hsts hsts) {
    this(cors, cookie, hsts, null, null);
  }

  @ConstructorBinding
  public EdgePerimeterProperties {
    cors = cors == null ? new Cors(List.of()) : cors;
    cookie = cookie == null ? new Cookie(true) : cookie;
    hsts = hsts == null ? new Hsts(true) : hsts;
    identity = identity == null ? new Identity(null) : identity;
    serviceJwt = serviceJwt == null ? new ServiceJwt(null) : serviceJwt;
  }

  /**
   * @param allowedOrigins explicit origin list; {@code *} is rejected at startup because the
   *     CORS configuration is credentialed
   */
  public record Cors(List<String> allowedOrigins) {
    public Cors {
      allowedOrigins = allowedOrigins == null ? List.of() : List.copyOf(allowedOrigins);
    }
  }

  /**
   * @param secure whether browser cookies (session, XSRF-TOKEN) carry the {@code Secure}
   *     attribute; defaults to true — plain-HTTP deployments must opt out explicitly. Modeled as a
   *     {@link Boolean} so the safe default also holds when the {@code edge.cookie} block is present
   *     but omits {@code secure}; a primitive would bind to {@code false} in that case, silently
   *     dropping the Secure attribute.
   */
  public record Cookie(Boolean secure) {
    public Cookie {
      secure = secure == null ? Boolean.TRUE : secure;
    }
  }

  /**
   * @param unconditional when true, HSTS is emitted on every response regardless of
   *     {@code X-Forwarded-Proto}, so a stripped or misclassified proxy header cannot silently
   *     suppress transport pinning; set false only for plain-HTTP local runs.
   */
  public record Hsts(Boolean unconditional) {
    public Hsts {
      unconditional = unconditional == null ? Boolean.TRUE : unconditional;
    }
  }

  /**
   * @param issuerUri trusted issuer for both browser OIDC ID tokens and service-plane JWTs; kept
   *     outside Spring's OAuth2 client provider block so the explicit endpoint configuration still
   *     boots offline without discovery
   */
  public record Identity(String issuerUri) {
    public Identity {
      if (issuerUri == null) {
        issuerUri = DEFAULT_ISSUER_URI;
      } else if (issuerUri.isBlank()) {
        throw new IllegalArgumentException("edge.identity.issuer-uri must not be blank");
      } else if (!issuerUri.equals(issuerUri.strip())) {
        throw new IllegalArgumentException(
            "edge.identity.issuer-uri must not include leading or trailing whitespace");
      } else if (containsControlCharacter(issuerUri)) {
        throw new IllegalArgumentException(
            "edge.identity.issuer-uri must not contain control characters");
      }
      validateIssuerUri(issuerUri);
    }
  }

  /**
   * @param audiences accepted service-plane JWT audiences; at least one audience is required so a
   *     token minted for another resource cannot satisfy the service role gate
   */
  public record ServiceJwt(List<String> audiences) {
    public ServiceJwt {
      if (audiences == null) {
        audiences = List.of(DEFAULT_SERVICE_AUDIENCE);
      } else {
        if (audiences.isEmpty()) {
          throw new IllegalArgumentException("edge.service-jwt.audiences must not be empty");
        }
        if (audiences.stream().anyMatch(audience -> audience == null || audience.isBlank())) {
          throw new IllegalArgumentException(
              "edge.service-jwt.audiences must not contain blank entries");
        }
        if (audiences.stream().anyMatch(audience -> !audience.equals(audience.strip()))) {
          throw new IllegalArgumentException(
              "edge.service-jwt.audiences must not include leading or trailing whitespace");
        }
        if (audiences.stream().anyMatch(EdgePerimeterProperties::containsControlCharacter)) {
          throw new IllegalArgumentException(
              "edge.service-jwt.audiences must not contain control characters");
        }
        audiences = List.copyOf(audiences);
      }
    }
  }

  private static boolean containsControlCharacter(String value) {
    return value.chars().anyMatch(Character::isISOControl);
  }

  private static void validateIssuerUri(String issuerUri) {
    final URI parsed;
    try {
      parsed = URI.create(issuerUri);
    } catch (IllegalArgumentException ex) {
      throw new IllegalArgumentException(
          "edge.identity.issuer-uri must be an absolute HTTP(S) URI: " + issuerUri, ex);
    }
    String scheme = parsed.getScheme();
    if (!"https".equalsIgnoreCase(scheme) && !"http".equalsIgnoreCase(scheme)
        || parsed.getHost() == null) {
      throw new IllegalArgumentException(
          "edge.identity.issuer-uri must be an absolute HTTP(S) URI: " + issuerUri);
    }
    if (!hasValidExplicitHttpPort(parsed)) {
      throw new IllegalArgumentException(
          "edge.identity.issuer-uri must include a valid HTTP(S) port when a port is explicit: "
              + issuerUri);
    }
    if ("http".equalsIgnoreCase(scheme) && !isLoopbackHost(parsed.getHost())) {
      throw new IllegalArgumentException(
          "edge.identity.issuer-uri must use HTTPS except for loopback local development: "
              + issuerUri);
    }
    if (parsed.getRawUserInfo() != null) {
      throw new IllegalArgumentException(
          "edge.identity.issuer-uri must not include user-info credentials: " + issuerUri);
    }
    if (parsed.getRawQuery() != null || parsed.getRawFragment() != null) {
      throw new IllegalArgumentException(
          "edge.identity.issuer-uri must not include query or fragment components: " + issuerUri);
    }
  }

  private static boolean isLoopbackHost(String host) {
    return "localhost".equalsIgnoreCase(host)
        || "127.0.0.1".equals(host)
        || "::1".equals(host)
        || "[::1]".equals(host);
  }

  private static boolean hasValidExplicitHttpPort(URI parsed) {
    String rawAuthority = parsed.getRawAuthority();
    return parsed.getPort() <= 65535 && (rawAuthority == null || !rawAuthority.endsWith(":"));
  }
}
