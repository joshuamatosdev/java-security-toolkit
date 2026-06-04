package io.github.joshuamatosdev.security.edge.config;

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
      issuerUri =
          issuerUri == null || issuerUri.isBlank() ? DEFAULT_ISSUER_URI : issuerUri.trim();
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
        audiences =
            audiences.stream().map(String::trim).filter(audience -> !audience.isBlank()).toList();
        if (audiences.isEmpty()) {
          throw new IllegalArgumentException("edge.service-jwt.audiences must not be empty");
        }
        audiences = List.copyOf(audiences);
      }
    }
  }
}
