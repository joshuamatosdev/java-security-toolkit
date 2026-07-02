# Tenant Isolation Spring Boot Example

The [tenant-isolation implementation walkthrough](../../tenant-isolation/README.md#implementation-walkthrough)
as a compilable, tested consumer application. It owns exactly the four things the walkthrough
assigns to an adopter:

1. **Depend** — [`build.gradle.kts`](build.gradle.kts) pulls one starter.
2. **Configure** — [`application.yaml`](src/main/resources/application.yaml) binds datasource,
   claim secret, and the `organization-scope` rollout dial from the environment.
3. **One filter** — [`TenantBindingFilter`](src/main/java/example/TenantBindingFilter.java) resolves
   tenant and organization from the verified JWT and binds them atomically.
4. **The database side** — [`db/init.sql`](src/test/resources/db/init.sql) is the reference DDL
   adapted to this application's `note` table: roles, claim secret, verifiers, RLS policies.

[`NoteController`](src/main/java/example/NoteController.java) is the payoff: no `WHERE tenant_id`,
no tenant column in the API, no way to even express a cross-tenant write.

## Run

Requires JDK 21 and Docker. From the repository root (the example includes the repository root as a
composite build, so it uses the current checkout and does not require a local Maven publication):

```bash
./gradlew -p examples/tenant-isolation-spring-boot test
```

## What the tests prove

`TenantIsolationFlowTest` drives real HTTP through the filter into PostgreSQL 18 with RLS enforced
by the non-superuser runtime role:

- Two tenants write and read through the same zero-predicate SQL; each sees only its own rows.
- An organization-bound session sees only its organization's slice of the tenant; an
  organization-unscoped session sees the whole tenant; nothing crosses the tenant boundary.
- Row `id`, `tenant_id`, and `organization_id` are database-stamped — the application never sends
  them.
- A JWT without a tenant claim is rejected with 403; an unauthenticated request never reaches the
  database.

`TenantContextContractTest` reuses the published `tenant-isolation-testkit` contract, the way an
adopter proves context binding in their own CI.

## Production notes

- Configure `spring.security.oauth2.resourceserver.jwt.issuer-uri` for your issuer and delete the
  test-only `JwtDecoder`; the tests fabricate tokens with spring-security-test instead.
- Install the claim secret from secret management (the committed value is a fictional local-dev
  constant) and keep the Java signer and database verifier in sync.
- Copy the omitted reference-DDL sections (system-writer tier, cross-tenant read entitlements) from
  `tenant-isolation/src/test/resources/db/init.sql` if you adopt those patterns.
