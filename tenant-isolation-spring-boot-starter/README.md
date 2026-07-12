# Tenant Isolation Spring Boot Starter

Auto-configures the [`tenant-isolation`](../tenant-isolation/) datasource boundary from
`tenant.isolation.*` and `tenant.binding.*` properties. It provides one application-scoped
`TenantContext`, guarded routing, signed session claims, and read-only pool inspection.

Applications bind the injected `TenantContext` before entering transactional work. The starter
backs off when an application supplies its own supported bean.

Verify with `./gradlew :tenant-isolation-spring-boot-starter:test`.
