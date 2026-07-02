package io.github.joshuamatosdev.security.edge.web;

import java.util.Map;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A generic authenticated browser-plane surface (no special role). Used to prove two things:
 * explicitly registered authenticated endpoints are reachable by any authenticated session, and a
 * mutating request is gated by CSRF (the {@code POST} reaching the controller means a valid CSRF
 * token was presented).
 *
 * <p>Why this exists: small controllers expose the exact browser, admin, public, and service
 * surfaces that the security chains protect.
 */
@RestController
public class DocumentController {

  @GetMapping("/api/documents")
  public Map<String, String> list() {
    return Map.of("documents", "none");
  }

  @PostMapping("/api/documents")
  public Map<String, String> create() {
    return Map.of("created", "ok");
  }

  @DeleteMapping("/api/documents/{id}")
  public Map<String, String> delete(@PathVariable String id) {
    return Map.of("deleted", id);
  }
}
