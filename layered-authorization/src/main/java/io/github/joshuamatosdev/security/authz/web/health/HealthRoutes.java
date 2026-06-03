package io.github.joshuamatosdev.security.authz.web.health;

/**
 * Public health endpoint constants shared by the controller, coarse gate, and HTTP tests.
 */
public final class HealthRoutes {

    public static final String HEALTH_PATH = "/health";
    public static final String STATUS_FIELD = "status";
    public static final String UP_STATUS = "UP";

    private HealthRoutes() {}
}
