package io.github.joshuamatosdev.security.tenant.datasource.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.TenantIds;
import io.github.joshuamatosdev.security.tenant.binding.OrganizationScope;
import io.github.joshuamatosdev.security.tenant.binding.TenantBindingObserver;
import io.github.joshuamatosdev.security.tenant.binding.TenantContext;
import io.github.joshuamatosdev.security.tenant.datasource.pool.TenantPoolInspection;
import io.github.joshuamatosdev.security.tenant.testfixtures.TenantTestConstants;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Clock;
import java.time.Duration;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the organization dimension of {@link TenantSessionDataSourceProxy}:
 *
 * <ol>
 *   <li>{@code off} never emits an organization claim, even when one is bound;
 *   <li>{@code optional} emits the {@code v2o} claim exactly when the binding carries an
 *       organization;
 *   <li>{@code required} fails closed before any connection is borrowed when an ordinary tenant
 *       binding has no organization — and exempts the system-operations tenant;
 *   <li>connection return clears the organization claim whenever this borrow bound one.
 * </ol>
 *
 * <p>Why this is important to test: the organization claim is the only input organization-aware row
 * policies can trust, so it must be present exactly when the posture says so and never survive a
 * connection's return to the pool.
 */
class TenantSessionDataSourceProxyOrganizationTest {

    private static final String POOL_NAME = "tenant";
    private static final String TENANT_CLAIM_SETTING = "app.tenant_claim";
    private static final String ORGANIZATION_CLAIM_SETTING = "app.org_claim";
    private static final OrganizationId ENGINEERING =
            OrganizationId.fromString("0190a000-0000-7000-8000-0000000000e1");
    private static final TenantClaimSigner CLAIM_SIGNER = new TenantClaimSigner(
            TenantTestConstants.CLAIM_SECRET, Duration.ofMinutes(30), Clock.systemUTC());

    private DataSource delegate;
    private Connection connection;
    private PreparedStatement statement;

    @BeforeEach
    void wireFakeConnection() throws SQLException {
        delegate = mock(DataSource.class);
        connection = mock(Connection.class);
        statement = mock(PreparedStatement.class);
        when(delegate.getConnection()).thenReturn(connection);
        when(connection.prepareStatement("SELECT set_config(?, ?, ?)")).thenReturn(statement);
        when(connection.getAutoCommit()).thenReturn(true);
    }

    @AfterEach
    void clearTenantContext() {
        TenantContext.clear();
    }

    @Test
    void offScopeNeverBindsAnOrganizationClaim() throws SQLException {
        final TenantSessionDataSourceProxy proxy = proxy(OrganizationScope.OFF);

        borrowAs(TenantIds.ACME, ENGINEERING, proxy);

        verify(statement).setString(1, TENANT_CLAIM_SETTING);
        verify(statement, never()).setString(1, ORGANIZATION_CLAIM_SETTING);
    }

    @Test
    void optionalScopeBindsTheOrganizationClaimWhenBound() throws SQLException {
        final TenantSessionDataSourceProxy proxy = proxy(OrganizationScope.OPTIONAL);

        borrowAs(TenantIds.ACME, ENGINEERING, proxy);

        verify(statement).setString(1, TENANT_CLAIM_SETTING);
        verify(statement).setString(eq(2), startsWith("v2:" + TenantIds.ACME + ":"));
        verify(statement).setString(1, ORGANIZATION_CLAIM_SETTING);
        verify(statement).setString(eq(2), startsWith("v2o:" + ENGINEERING + ":"));
    }

    @Test
    void optionalScopeSkipsTheOrganizationClaimWhenAbsent() throws SQLException {
        final TenantSessionDataSourceProxy proxy = proxy(OrganizationScope.OPTIONAL);

        borrowAs(TenantIds.ACME, null, proxy);

        verify(statement).setString(1, TENANT_CLAIM_SETTING);
        verify(statement, never()).setString(1, ORGANIZATION_CLAIM_SETTING);
    }

    @Test
    void requiredScopeFailsClosedBeforeBorrowWhenOrganizationIsAbsent() throws SQLException {
        final TenantBindingObserver observer = mock(TenantBindingObserver.class);
        final TenantSessionDataSourceProxy proxy = new TenantSessionDataSourceProxy(
                delegate, POOL_NAME, CLAIM_SIGNER, OrganizationScope.REQUIRED,
                observer, TenantPoolInspection.NONE);

        TenantContext.runAs(TenantIds.ACME, () ->
                assertThatThrownBy(proxy::getConnection)
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("requires organization binding")
                        .hasMessageContaining("organization-scope=required"));

        verify(delegate, never()).getConnection();
        verify(observer).onOrganizationBindingMissing(POOL_NAME);
    }

    @Test
    void requiredScopeBindsBothClaimsWhenOrganizationIsBound() throws SQLException {
        final TenantSessionDataSourceProxy proxy = proxy(OrganizationScope.REQUIRED);

        borrowAs(TenantIds.ACME, ENGINEERING, proxy);

        verify(statement).setString(eq(2), startsWith("v2:" + TenantIds.ACME + ":"));
        verify(statement).setString(eq(2), startsWith("v2o:" + ENGINEERING + ":"));
    }

    @Test
    void systemOpsIsExemptFromRequiredScope() throws SQLException {
        final TenantSessionDataSourceProxy proxy = proxy(OrganizationScope.REQUIRED);

        final Connection borrowed = TenantContext.supplyAsSystemOps(() -> borrowQuietly(proxy));

        assertThat(borrowed).isNotNull();
        verify(statement).setString(1, TENANT_CLAIM_SETTING);
        verify(statement, never()).setString(1, ORGANIZATION_CLAIM_SETTING);
    }

    @Test
    void closeClearsTheOrganizationClaimWhenThisBorrowBoundOne() throws SQLException {
        final TenantSessionDataSourceProxy proxy = proxy(OrganizationScope.OPTIONAL);

        final Connection borrowed = borrowAs(TenantIds.ACME, ENGINEERING, proxy);
        borrowed.close();

        // Both settings are cleared: two setNull calls, and each setting name passes through
        // setString(1, ...) twice — once at bind, once at clear.
        verify(statement, times(2)).setNull(2, Types.VARCHAR);
        verify(statement, times(2)).setString(1, TENANT_CLAIM_SETTING);
        verify(statement, times(2)).setString(1, ORGANIZATION_CLAIM_SETTING);
    }

    @Test
    void closeDoesNotTouchTheOrganizationSettingForTenantOnlyBorrows() throws SQLException {
        final TenantSessionDataSourceProxy proxy = proxy(OrganizationScope.OPTIONAL);

        final Connection borrowed = borrowAs(TenantIds.ACME, null, proxy);
        borrowed.close();

        verify(statement, never()).setString(1, ORGANIZATION_CLAIM_SETTING);
    }

    private TenantSessionDataSourceProxy proxy(final OrganizationScope scope) {
        return new TenantSessionDataSourceProxy(
                delegate, POOL_NAME, CLAIM_SIGNER, scope, TenantPoolInspection.NONE);
    }

    private Connection borrowAs(
            final TenantId tenant,
            final OrganizationId organization,
            final TenantSessionDataSourceProxy proxy) {
        if (organization == null) {
            return TenantContext.supplyAs(tenant, () -> borrowQuietly(proxy));
        }
        return TenantContext.supplyAs(tenant, organization, () -> borrowQuietly(proxy));
    }

    private static Connection borrowQuietly(final TenantSessionDataSourceProxy proxy) {
        try {
            return proxy.getConnection();
        } catch (SQLException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
