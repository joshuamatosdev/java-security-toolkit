package io.github.joshuamatosdev.security.tenant.binding;

import static org.assertj.core.api.Assertions.assertThat;

import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import io.github.joshuamatosdev.security.tenant.TenantIds;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class SystemTenantBoundaryArchitectureTest {

    private static final String DATA_SOURCE_CONFIG_SOURCE =
            "io/github/joshuamatosdev/security/tenant/datasource/factory/DataSourceConfig.java";
    private static final String FAILED_TO_READ_PREFIX = "Failed to read ";
    private static final String JAVA_SUFFIX = ".java";
    private static final String MAIN_SOURCE_ROOT = "src/main/java";
    private static final String PACKAGE = "io.github.joshuamatosdev.security.tenant";
    private static final String RUN_AS_SYSTEM_OPS_METHOD = "runAsSystemOps";
    private static final String SUPPLY_AS_SYSTEM_OPS_METHOD = "supplyAsSystemOps";
    private static final String SYSTEM_OPS_FIELD = "SYSTEM_OPS";
    private static final String TENANT_BYPASS_ROLE = "tenant_bypass";
    private static final String TENANT_OPS_USER = "tenant_ops_user";
    private static final String TENANT_POOL_FACTORY_SOURCE =
            "io/github/joshuamatosdev/security/tenant/datasource/factory/TenantPoolFactory.java";
    private static final String TENANT_RUNTIME_POOL_BEAN = "tenantRuntimePool";
    private static final String TENANT_SYSTEM_OPS_POOL_BEAN = "tenantSystemOpsPool";

    @Test
    void productionClassesTouchingSystemOpsBoundaryAreAnnotated() {
        final var classes = new ClassFileImporter()
                .withImportOption(new ImportOption.DoNotIncludeTests())
                .importPackages(PACKAGE);

        final var offenders = classes.stream()
                .filter(SystemTenantBoundaryArchitectureTest::touchesSystemOpsBoundary)
                .filter(javaClass -> !javaClass.isAnnotatedWith(SystemTenantBoundary.class))
                .map(JavaClass::getName)
                .sorted()
                .toList();

        assertThat(offenders)
                .as("Only @SystemTenantBoundary types may touch SYSTEM_OPS or system-ops entry points")
                .isEmpty();
    }

    @Test
    void rawSystemOpsBypassStringsStayInAnnotatedProductionSources() throws Exception {
        final Path sourceRoot = Path.of(MAIN_SOURCE_ROOT);
        final Set<String> allowedSources = Set.of(
                "io/github/joshuamatosdev/security/tenant/TenantIds.java",
                "io/github/joshuamatosdev/security/tenant/binding/TenantContext.java",
                "io/github/joshuamatosdev/security/tenant/binding/SystemTenantBoundary.java",
                DATA_SOURCE_CONFIG_SOURCE,
                "io/github/joshuamatosdev/security/tenant/datasource/routing/SystemOpsRoutingDataSource.java",
                "io/github/joshuamatosdev/security/tenant/datasource/routing/TenantDatabaseRoutingDataSource.java",
                TENANT_POOL_FACTORY_SOURCE,
                "io/github/joshuamatosdev/security/tenant/datasource/routing/TenantSchemaDataSource.java");

        try (var paths = Files.walk(sourceRoot)) {
            final var offenders = paths.filter(path -> path.toString().endsWith(JAVA_SUFFIX))
                    .filter(path -> containsSystemOpsBypassString(path) && !allowedSources.contains(toRelativeName(sourceRoot, path)))
                    .map(path -> toRelativeName(sourceRoot, path))
                    .sorted(Comparator.naturalOrder())
                    .collect(Collectors.toList());

            assertThat(offenders)
                    .as("Raw system-ops bypass strings belong only in annotated boundary sources")
                    .isEmpty();
        }
    }

    @Test
    void rawTenantPoolsStayInsideDatasourceInfrastructure() throws Exception {
        final Path sourceRoot = Path.of(MAIN_SOURCE_ROOT);
        final Set<String> allowedSources = Set.of(
                DATA_SOURCE_CONFIG_SOURCE,
                "io/github/joshuamatosdev/security/tenant/datasource/pool/HikariTenantPoolInspection.java",
                "io/github/joshuamatosdev/security/tenant/datasource/pool/HikariTenantPoolSnapshotSource.java",
                "io/github/joshuamatosdev/security/tenant/datasource/factory/TenantDataSourceFactory.java",
                TENANT_POOL_FACTORY_SOURCE);

        try (var paths = Files.walk(sourceRoot)) {
            final var offenders = paths.filter(path -> path.toString().endsWith(JAVA_SUFFIX))
                    .filter(path -> !allowedSources.contains(toRelativeName(sourceRoot, path)))
                    .filter(SystemTenantBoundaryArchitectureTest::containsRawPoolInjectionSurface)
                    .map(path -> toRelativeName(sourceRoot, path))
                    .sorted(Comparator.naturalOrder())
                    .collect(Collectors.toList());

            assertThat(offenders)
                    .as("Raw tenant Hikari pools must not be referenced outside datasource infrastructure")
                    .isEmpty();
        }
    }

    private static boolean touchesSystemOpsBoundary(final JavaClass javaClass) {
        final boolean accessesSystemOps = javaClass.getFieldAccessesFromSelf().stream()
                .anyMatch(access -> access.getTarget().getOwner().isEquivalentTo(TenantIds.class)
                        && SYSTEM_OPS_FIELD.equals(access.getTarget().getName()));
        final boolean callsSystemOpsEntryPoint = javaClass.getMethodCallsFromSelf().stream()
                .anyMatch(call -> call.getTarget().getOwner().isEquivalentTo(TenantContext.class)
                        && Set.of(RUN_AS_SYSTEM_OPS_METHOD, SUPPLY_AS_SYSTEM_OPS_METHOD)
                                .contains(call.getTarget().getName()));
        return accessesSystemOps || callsSystemOpsEntryPoint;
    }

    private static boolean containsSystemOpsBypassString(final Path path) {
        try {
            final String source = Files.readString(path);
            return source.contains(SYSTEM_OPS_FIELD)
                    || source.contains(RUN_AS_SYSTEM_OPS_METHOD)
                    || source.contains(SUPPLY_AS_SYSTEM_OPS_METHOD)
                    || source.contains(TENANT_BYPASS_ROLE)
                    || source.contains(TENANT_OPS_USER);
        } catch (Exception ex) {
            throw new IllegalStateException(FAILED_TO_READ_PREFIX + path, ex);
        }
    }

    private static boolean containsRawPoolInjectionSurface(final Path path) {
        try {
            final String source = Files.readString(path);
            return source.contains("HikariDataSource")
                    || source.contains(TENANT_RUNTIME_POOL_BEAN)
                    || source.contains(TENANT_SYSTEM_OPS_POOL_BEAN);
        } catch (Exception ex) {
            throw new IllegalStateException(FAILED_TO_READ_PREFIX + path, ex);
        }
    }

    private static String toRelativeName(final Path sourceRoot, final Path path) {
        return sourceRoot.relativize(path).toString().replace('\\', '/');
    }
}
