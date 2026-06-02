package io.github.joshuamatosdev.security.tenant;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.tenant.testfixtures.WithTenant;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

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

    @Autowired
    private DataSource dataSource;

    @Test
    void runtimePoolRoleCannotBypassRls() {
        // A tenant must be bound for the fail-closed proxy to hand out a connection at all.
        WithTenant.runAs(TenantIds.ACME, () -> {
            try (Connection c = dataSource.getConnection();
                    Statement st = c.createStatement();
                    ResultSet rs = st.executeQuery(
                            "SELECT current_user AS who, rolsuper, rolbypassrls "
                                    + "FROM pg_roles WHERE rolname = current_user")) {
                assertThat(rs.next()).isTrue();
                assertThat(rs.getString("who")).isEqualTo("tenant_user");
                assertThat(rs.getBoolean("rolsuper"))
                        .as("runtime pool role must not be a superuser")
                        .isFalse();
                assertThat(rs.getBoolean("rolbypassrls"))
                        .as("runtime pool role must not carry BYPASSRLS")
                        .isFalse();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
    }
}
