# Tenant Isolation Testkit

Reusable contract tests for applications that adopt [`tenant-isolation`](../tenant-isolation/).
The contracts exercise ordinary tenant binding, system-operations rejection, and context
restoration against an adopter-provided `TenantContext` instance.

Depend on this module in test scope and implement `TenantContextContract`.

Verify with `./gradlew :tenant-isolation-testkit:test`.
