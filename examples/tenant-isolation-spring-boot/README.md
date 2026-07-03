# Tenant Isolation Spring Boot Example

This is the [tenant-isolation implementation walkthrough](../../tenant-isolation/README.md#implementation-walkthrough).
It is a real consumer app. It compiles and passes tests. It owns exactly four
adopter tasks. The walkthrough assigns these four:

1. **Depend** — [`build.gradle.kts`](build.gradle.kts) pulls one starter.
2. **Configure** — [`application.yaml`](src/main/resources/application.yaml) binds three
   things. It binds the datasource. It binds the claim secret. It binds the
   `organization-scope` rollout dial. All from the environment.
3. **One filter** — [`TenantBindingFilter`](src/main/java/example/TenantBindingFilter.java)
   does two jobs. It resolves tenant and organization. It reads the verified JWT. It
   binds them atomically.
4. **The database side** — see [`db/init.sql`](src/test/resources/db/init.sql). It is
   the reference DDL. It fits this app's `note` table. It sets roles and claim secret. It
   sets verifiers and RLS policies.

[`NoteController`](src/main/java/example/NoteController.java) is the payoff. It has no
`WHERE tenant_id`. It has no tenant column. Not in the API. A cross-tenant write cannot
be expressed.

## Run

Requires JDK 21 and Docker. The example uses a composite build. It includes the
repository root. So it uses the current checkout. No local Maven publication is needed.
Run from the repository root:

```bash
./gradlew -p examples/tenant-isolation-spring-boot test
```

## What the tests prove

`TenantIsolationFlowTest` drives real HTTP. It goes through the filter. It reaches
PostgreSQL 18. RLS is enforced there. The non-superuser runtime role enforces it:

- Two tenants share the same SQL. It is zero-predicate SQL. They write and read through
  it. Each sees only its own rows.
- An organization-bound session sees one slice. Only its own organization's rows. An
  organization-unscoped session sees more. It sees the whole tenant. Nothing crosses
  the tenant boundary.
- Three columns are database-stamped. They are `id`, `tenant_id`, `organization_id`.
  The application never sends them.
- A tenant claim may be missing. Then the JWT gets 403. Unauthenticated requests never
  reach the database.

`TenantContextContractTest` reuses a published contract. It comes from
`tenant-isolation-testkit`. Adopters prove context binding this way. They run it in
their CI.

## Production notes

- Set `spring.security.oauth2.resourceserver.jwt.issuer-uri` for your issuer. Delete
  the test-only `JwtDecoder`. The tests fabricate tokens instead. They use
  spring-security-test.
- Install the claim secret properly. Use your secret management. The committed value is
  fictional. It is a local-dev constant. Keep the Java signer in sync. Keep the database
  verifier too.
- Some reference-DDL sections are omitted here. These cover the system-writer tier. And
  cross-tenant read entitlements. Copy them for those patterns. They live in
  `tenant-isolation/src/test/resources/db/init.sql`.
