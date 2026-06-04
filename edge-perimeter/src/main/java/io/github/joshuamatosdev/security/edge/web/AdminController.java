package io.github.joshuamatosdev.security.edge.web;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Administrative surface. {@code /api/admin/dashboard} is admin-only (the broad gate);
 * {@code /api/admin/audit-export} is the narrow exception auditors may also reach. Whether a
 * request reaches these methods is decided entirely by the route map in
 * {@code BrowserSecurityChainConfig}; the handlers exist only so an allowed request yields 200.
 */
@RestController
public class AdminController {

  @GetMapping("/api/admin/dashboard")
  public Map<String, String> dashboard() {
    return Map.of("panel", "admin");
  }

  @GetMapping("/api/admin/audit-export")
  public Map<String, String> auditExport() {
    return Map.of("export", "audit-log");
  }
}
