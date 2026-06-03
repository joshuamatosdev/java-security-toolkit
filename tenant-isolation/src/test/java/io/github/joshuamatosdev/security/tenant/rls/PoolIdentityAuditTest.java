package io.github.joshuamatosdev.security.tenant.rls;

import io.github.joshuamatosdev.security.tenant.testfixtures.AbstractRlsTest;

import io.github.joshuamatosdev.security.tenant.TenantIds;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.tenant.binding.TenantContext;
import io.github.joshuamatosdev.security.tenant.testfixtures.WithTenant;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * RLS is enforced only for a role that is neither a superuser nor {@code BYPASSRLS}. A correct
 * policy is worthless if the pool connects as a superuser — the engine skips policy evaluation
 * entirely. This test fails if the runtime pool identity could bypass RLS.
 *
 * <p>In production the equivalent guard is a static audit of the datasource configuration that
 * ships with the artifact: an integration test connects as the test database's bootstrap superuser
 * and would pass while production stayed vulnerable. Here the runtime pool is deliberately wired as
 * the non-superuser {@code tenant_user}, so a live runtime assertion is the truthful check.
 */
class PoolIdentityAuditTest extends AbstractRlsTest {

    private static final String CAN_BYPASS_COLUMN = "can_bypass";
    private static final String CURRENT_USER_COLUMN = "who";
    private static final String ROLE_BYPASS_RLS_COLUMN = "rolbypassrls";
    private static final String ROLE_SUPER_COLUMN = "rolsuper";
    private static final String SQL_COLUMN_SEPARATOR = ", ";
    private static final String TENANT_BYPASS_ROLE = "tenant_bypass";
    private static final String ROLE_ATTRIBUTE_SQL = "SELECT current_user AS " + CURRENT_USER_COLUMN
            + SQL_COLUMN_SEPARATOR
            + ROLE_SUPER_COLUMN + SQL_COLUMN_SEPARATOR + ROLE_BYPASS_RLS_COLUMN + SQL_COLUMN_SEPARATOR
            + "pg_has_role(current_user, '" + TENANT_BYPASS_ROLE + "', 'USAGE') AS " + CAN_BYPASS_COLUMN + " "
            + "FROM pg_roles WHERE rolname = current_user";

    @Autowired
    private DataSource dataSource;

    @Autowired
    private ConfigurableApplicationContext context;

    @Test
    void rawPoolsAreNotAutowireCandidates() {
        final var beanFactory = context.getBeanFactory();

        assertThat(beanFactory.getBeanDefinition("tenantRuntimePool").isAutowireCandidate())
                .as("raw tenant runtime pool must not be directly injectable")
                .isFalse();
        assertThat(beanFactory.getBeanDefinition("tenantSystemOpsPool").isAutowireCandidate())
                .as("raw system-ops bypass-role pool must not be directly injectable")
                .isFalse();
    }

    @Test
    void runtimePoolRoleCannotBypassRls() {
        // A tenant must be bound for the fail-closed proxy to hand out a connection at all.
        WithTenant.runAs(TenantIds.ACME, () -> {
            try (Connection c = dataSource.getConnection();
                    Statement st = c.createStatement();
                    ResultSet rs = st.executeQuery(
                            ROLE_ATTRIBUTE_SQL)) {
                assertThat(rs.next()).isTrue();
                assertThat(rs.getString(CURRENT_USER_COLUMN)).isEqualTo(RUNTIME_USERNAME);
                assertThat(rs.getBoolean(ROLE_SUPER_COLUMN))
                        .as("runtime pool role must not be a superuser")
                        .isFalse();
                assertThat(rs.getBoolean(ROLE_BYPASS_RLS_COLUMN))
                        .as("runtime pool role must not carry BYPASSRLS")
                        .isFalse();
                assertThat(rs.getBoolean(CAN_BYPASS_COLUMN))
                        .as("ordinary runtime pool role must not be a tenant_bypass member")
                        .isFalse();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
    }

    @Test
    void systemOpsPoolUsesReadOnlyBypassRoleMembership() {
        TenantContext.runAsSystemOps(() -> {
            try (Connection c = dataSource.getConnection();
                    Statement st = c.createStatement();
                    ResultSet rs = st.executeQuery(
                            ROLE_ATTRIBUTE_SQL)) {
                assertThat(rs.next()).isTrue();
                assertThat(rs.getString(CURRENT_USER_COLUMN)).isEqualTo(SYSTEM_OPS_USERNAME);
                assertThat(rs.getBoolean(ROLE_SUPER_COLUMN))
                        .as("system-ops pool role must not be a superuser")
                        .isFalse();
                assertThat(rs.getBoolean(ROLE_BYPASS_RLS_COLUMN))
                        .as("system-ops pool role must not carry BYPASSRLS")
                        .isFalse();
                assertThat(rs.getBoolean(CAN_BYPASS_COLUMN))
                        .as("system-ops pool role must be a tenant_bypass member")
                        .isTrue();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
    }
}
