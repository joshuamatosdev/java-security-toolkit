package io.github.joshuamatosdev.security.authz.web.gate;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.type.filter.AnnotationTypeFilter;
import org.springframework.http.HttpMethod;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.ClassUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Proves the gate's completeness invariant: every {@code @RestController} endpoint in this
 * application is matched by a {@link SecurityUrlGroup} — either a public group with the right
 * method, or a {@link AccessRule#RESTRICTED_RULES} entry. The {@code anyRequest().denyAll()}
 * catch-all makes a forgotten route fail <em>closed</em>, which is safe but silently dead: the
 * endpoint 403s in production instead of failing this build. This test turns that silence into a
 * red bar at the moment the endpoint is added.
 *
 * <p>Controllers are discovered by classpath scan, so a new controller cannot dodge the check by
 * not being listed here.
 */
class AccessRuleCoverageTest {

    private static final String WEB_PACKAGE = "io.github.joshuamatosdev.security.authz.web";
    private static final AntPathMatcher PATHS = new AntPathMatcher();

    private record Endpoint(String controller, String handler, HttpMethod method, String url) {
        @Override
        public String toString() {
            return method + " " + url + " (" + controller + "#" + handler + ")";
        }
    }

    @Test
    void everyControllerEndpointIsMatchedByTheGate() {
        final List<Endpoint> endpoints = scanEndpoints();
        // The scan itself must see the application, or the whole test is vacuous.
        assertThat(endpoints).isNotEmpty();

        final List<Endpoint> unmatched = endpoints.stream()
                .filter(endpoint -> !coveredByPublicGroup(endpoint) && !coveredByRestrictedRule(endpoint))
                .toList();

        assertThat(unmatched)
                .withFailMessage(
                        "These endpoints match no SecurityUrlGroup rule and would be dead at "
                                + "anyRequest().denyAll(): %s. Add a public group or an "
                                + "AccessRule.RESTRICTED_RULES entry for each.",
                        unmatched)
                .isEmpty();
    }

    private static boolean coveredByPublicGroup(final Endpoint endpoint) {
        for (final SecurityUrlGroup group : SecurityUrlGroup.values()) {
            if (group.isPublic()
                    && group.publicMethod().equals(endpoint.method())
                    && matchesGroup(group, endpoint.url())) {
                return true;
            }
        }
        return false;
    }

    private static boolean coveredByRestrictedRule(final Endpoint endpoint) {
        return AccessRule.RESTRICTED_RULES.stream()
                .anyMatch(rule -> (rule.method() == null || rule.method().equals(endpoint.method()))
                        && matchesGroup(rule.group(), endpoint.url()));
    }

    private static boolean matchesGroup(final SecurityUrlGroup group, final String url) {
        for (final String pattern : group.securityUrls()) {
            if (PATHS.match(pattern, url)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Every handler-method mapping in every {@code @RestController} under the web package,
     * class-level {@code @RequestMapping} prefix included. Verb annotations like
     * {@code @GetMapping} are meta-annotated with {@code @RequestMapping}, so the merged
     * annotation carries both the method and the path.
     */
    private static List<Endpoint> scanEndpoints() {
        final var scanner = new ClassPathScanningCandidateComponentProvider(false);
        scanner.addIncludeFilter(new AnnotationTypeFilter(RestController.class));

        final List<Endpoint> endpoints = new ArrayList<>();
        for (final var definition : scanner.findCandidateComponents(WEB_PACKAGE)) {
            final Class<?> controller = ClassUtils.resolveClassName(
                    definition.getBeanClassName(), AccessRuleCoverageTest.class.getClassLoader());
            final String prefix = classLevelPrefix(controller);
            for (final Method handler : controller.getDeclaredMethods()) {
                final Set<RequestMapping> mappings =
                        AnnotatedElementUtils.findAllMergedAnnotations(handler, RequestMapping.class);
                for (final RequestMapping mapping : mappings) {
                    endpoints.addAll(toEndpoints(controller, handler, prefix, mapping));
                }
            }
        }
        return endpoints;
    }

    private static String classLevelPrefix(final Class<?> controller) {
        final RequestMapping classMapping =
                AnnotatedElementUtils.findMergedAnnotation(controller, RequestMapping.class);
        if (classMapping == null || classMapping.path().length == 0) {
            return "";
        }
        return classMapping.path()[0];
    }

    private static List<Endpoint> toEndpoints(
            final Class<?> controller, final Method handler, final String prefix, final RequestMapping mapping) {
        final String[] paths = mapping.path().length == 0 ? new String[] {""} : mapping.path();
        final List<Endpoint> endpoints = new ArrayList<>();
        for (final var requestMethod : mapping.method()) {
            for (final String path : paths) {
                endpoints.add(new Endpoint(
                        controller.getSimpleName(),
                        handler.getName(),
                        HttpMethod.valueOf(requestMethod.name()),
                        joinPaths(prefix, path)));
            }
        }
        return endpoints;
    }

    private static String joinPaths(final String prefix, final String path) {
        final String joined = (prefix + (path.isEmpty() || path.startsWith("/") ? path : "/" + path));
        return joined.isEmpty() ? "/" : joined;
    }
}
