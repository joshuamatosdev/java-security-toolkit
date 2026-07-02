# Five-Layer Composed Example

The whole posture, booting: two applications that wire four Bulwark modules together and prove,
with integration tests, that the layers compose on a single request.

```
Browser / SPA
     |
     v            (session cookie, OIDC + PKCE, CORS, CSRF, headers)
+-----------+
|   bff     |     layers 1 + 4 — edge-spring-boot-starter
+-----------+
     | token relay: the user's access token, never the session cookie
     v            (bearer JWT: same pinned issuer, verified again)
+-----------+
|  service  |     layer 2 — authorization-spring-boot-starter (route gate + audited policy)
+-----------+     layer 5 — tenant-isolation-spring-boot-starter (verified binding + RLS)
     |
     v
 PostgreSQL       row-level security under a non-superuser pool
```

Layer 3 (secrets/config) is posture, not code: every credential here arrives by environment
variable, per ADR-0001 and the release checklist.

## What Each Test Proves

`service/` — `FiveLayerFlowTest` (Testcontainers PostgreSQL 18):

- One request crosses gate one (coarse route gate), gate two (fine-grained audited decision), and
  RLS — each with its own observable refusal, in that order.
- A foreign tenant's probe is invisible to the policy: RLS returns no row, the attempt is audited
  as `RESOURCE_NOT_FOUND`, and the response is indistinguishable from a nonexistent id.
- Policy grants are action-specific: an organization peer may READ but not DELETE; the denial is
  audited before the starter's advice translates it to 403.
- A tenant-admin allow is flagged wide-scope in the audit trail.
- A role-less (but authenticated, tenant-bound) token is refused at gate one — no decision, no
  audit record, no SQL.

`bff/` — `DocumentRelayFlowTest` (in-process downstream double):

- A session-authenticated request is relayed with the user's access token and nothing else — the
  session cookie never crosses the plane boundary.
- Anonymous requests are redirected to login and CSRF-less writes are refused, both before any
  downstream call.

The two applications share one identity contract — the same pinned issuer and the same
`tenant_id` / `organization_id` / `roles` claims. Each side's test drives its half of the hop with
that contract; the real OIDC/PKCE and JWT-decoder mechanics are proven in the edge module's own
tests against an in-process JWKS.

## Run the Tests

Requirements: JDK 21, Docker (for the service's PostgreSQL Testcontainers).

```bash
./gradlew -p examples/five-layer-spring-boot build
```

The example includes the repository root as a composite build, so it uses the current checkout and
does not require a local Maven publication.

## Run It Manually

Start PostgreSQL with the DDL, then each application:

```bash
docker run -d --name five-layer-pg -p 5432:5432 -e POSTGRES_PASSWORD=postgres \
  -v "$PWD/examples/five-layer-spring-boot/service/src/test/resources/db/init.sql:/docker-entrypoint-initdb.d/init.sql" \
  postgres:18-alpine

DB_URL=jdbc:postgresql://localhost:5432/postgres \
DB_RUNTIME_USER=tenant_user DB_RUNTIME_PASSWORD=local_dev_only \
TENANT_BINDING_CLAIM_SECRET=local-dev-tenant-claim-secret-not-production-32-bytes \
TENANT_BINDING_SYSTEM_OPS_PASSWORD=local_dev_only \
./gradlew -p examples/five-layer-spring-boot :service:bootRun

./gradlew -p examples/five-layer-spring-boot :bff:bootRun   # port 8080, relays to 8081
```

A full interactive login needs a real OIDC provider registered in the BFF's
`application.yaml` (the shipped endpoints are fictional so the context boots offline). Point both
applications at the same issuer and the relay carries identity end to end.
