package io.github.joshuamatosdev.security.tenant.binding;

import java.util.Objects;
import java.util.Optional;
import org.jspecify.annotations.Nullable;

/** Pure validation functions for tenant binding state transitions. */
final class BindingTransition {

    private BindingTransition() {}

    static Optional<String> bindViolation(
            final @Nullable TenantBinding current,
            final TenantBinding target,
            final boolean transactionActive) {
        Objects.requireNonNull(target, "target must not be null");
        if (!transactionActive) {
            return Optional.empty();
        }
        if (current == null) {
            return Optional.of("cannot bind tenant " + target.tenant()
                    + " inside an active transaction — the tenant must be bound before the transaction"
                    + " starts (fail-closed)");
        }
        if (!current.tenant().equals(target.tenant())) {
            return Optional.of("cannot switch tenant binding from " + current.tenant() + " to "
                    + target.tenant() + " inside an active transaction — the transaction already owns a"
                    + " tenant-bound database session (fail-closed)");
        }
        if (!Objects.equals(current.organization(), target.organization())) {
            return Optional.of("cannot switch organization binding from "
                    + describeOrganization(current.organization()) + " to "
                    + describeOrganization(target.organization())
                    + " inside an active transaction — the transaction already owns a tenant-bound"
                    + " database session (fail-closed)");
        }
        return Optional.empty();
    }

    static Optional<String> clearViolation(
            final @Nullable TenantBinding current, final boolean transactionActive) {
        if (current == null || !transactionActive) {
            return Optional.empty();
        }
        return Optional.of("cannot clear tenant binding for " + current.tenant()
                + " inside an active transaction — clearing could desynchronize the application"
                + " boundary from the database session (fail-closed)");
    }

    static Optional<String> restoreViolation(
            final @Nullable TenantBinding current,
            final @Nullable TenantBinding prior,
            final boolean transactionActive) {
        if (!transactionActive || Objects.equals(current, prior)) {
            return Optional.empty();
        }
        return Optional.of("cannot restore tenant binding from " + describe(current) + " to "
                + describe(prior) + " inside an active transaction — restoring could desynchronize"
                + " the application boundary from the database session (fail-closed)");
    }

    private static String describe(final @Nullable TenantBinding binding) {
        if (binding == null) {
            return "none";
        }
        if (binding.organization() == null) {
            return binding.tenant().toString();
        }
        return binding.tenant() + " (organization " + binding.organization() + ")";
    }

    private static String describeOrganization(final @Nullable Object organization) {
        return organization == null ? "none" : organization.toString();
    }
}
