package io.github.joshuamatosdev.security.edge.web;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A generic authenticated browser-plane surface (no special role). Used to prove two things:
 * any authenticated session reaches {@code anyExchange().authenticated()} endpoints, and a mutating
 * request is gated by CSRF (the {@code POST} reaching the controller means a valid CSRF token was
 * presented).
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
}
