package io.github.joshuamatosdev.security.edge.web;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Service-plane surface under {@code /api/service/**}, reachable only with a valid bearer JWT
 * carrying {@code ROLE_service}. No session, no CSRF: the token is the whole credential. Reaching
 * this handler proves the resource-server chain authenticated the token and the role mapped.
 */
@RestController
public class ServiceReportController {

  @GetMapping("/api/service/reports")
  public Map<String, String> reports() {
    return Map.of("report", "service-metrics");
  }
}
