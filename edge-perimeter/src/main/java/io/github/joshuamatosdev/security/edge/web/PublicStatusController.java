package io.github.joshuamatosdev.security.edge.web;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Anonymous surface under {@code /api/public/**}: the liveness probe an unauthenticated SPA polls
 * before login. Reaching this endpoint at all is the test that the public route is permitted; the
 * body is incidental.
 *
 * <p>Why this exists: small controllers expose the exact browser, admin, public, and service
 * surfaces that the security chains protect.
 */
@RestController
public class PublicStatusController {

  @GetMapping("/api/public/status")
  public Map<String, String> status() {
    return Map.of("status", "ok");
  }
}
