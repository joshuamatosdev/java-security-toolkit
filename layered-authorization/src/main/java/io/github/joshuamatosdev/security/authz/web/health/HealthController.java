package io.github.joshuamatosdev.security.authz.web.health;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Minimal liveness endpoint for the public health URL group.
 */
@RestController
public class HealthController {

    @GetMapping(HealthRoutes.HEALTH_PATH)
    public Map<String, String> health() {
        return Map.of(HealthRoutes.STATUS_FIELD, HealthRoutes.UP_STATUS);
    }
}
