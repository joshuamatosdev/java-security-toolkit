# Five-Layer Composed Example

This is the whole posture, booting. Two applications work together. They wire four
toolkit modules. Integration tests prove they compose. The layers compose on one
request.

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

Layer 3 is secrets and config. It is posture, not code. Every credential arrives by
environment variable and is checked against the release checklist.

## What Each Test Proves

`service/` runs `FiveLayerFlowTest`. It uses Testcontainers PostgreSQL 18:

- One request crosses three checks. Gate one: the coarse route gate. Gate two: a
  fine-grained audited decision. The third check is RLS. Each has its own observable
  refusal. They run in that order.
- A foreign tenant's probe stays invisible. The policy never sees it. RLS returns no
  row. The attempt is audited as `RESOURCE_NOT_FOUND`. Indistinguishable from a
  nonexistent id.
- Policy grants are action-specific. An organization peer may READ. But not DELETE.
  The denial is audited first. Then the starter's advice returns 403.
- A tenant-admin allow is flagged wide-scope. The audit trail records this.
- Consider a role-less token. It is authenticated and tenant-bound. Gate one still
  refuses it. No decision runs. No audit record is written. No SQL executes.

`bff/` runs `DocumentRelayFlowTest`. It uses an in-process downstream double:

- A session-authenticated request comes in. It relays the user's access token. Nothing
  else goes with it. The session cookie stays behind. It never crosses the plane
  boundary.
- Anonymous requests redirect to login. CSRF-less writes are refused. Both happen
  before any downstream call.

Both applications share one identity contract. They use the same pinned issuer and the
service accepts only the BFF's `edge-service-api` audience. They use the same claims.
These are `tenant_id`, `organization_id`, `roles`. Each test
drives its own half. It uses that shared contract. The real mechanics live elsewhere.
The edge module proves OIDC/PKCE. It proves the JWT-decoder too. Its tests use an
in-process JWKS.

## Run the Tests

Requirements: JDK 21 and Docker. Docker runs the service's PostgreSQL Testcontainers.

```bash
./gradlew -p examples/five-layer-spring-boot build
```

The example uses a composite build. It includes the repository root. So it uses the
current checkout. No local Maven publication is needed.

## Run It Manually

Start PostgreSQL with the DDL. Then start each application:

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

A full interactive login needs more. Register a real OIDC provider. Put it in the
BFF's `application.yaml`. The shipped endpoints are fictional. So the context boots
offline. Point both apps at one issuer, and override `JWT_AUDIENCE` only if the
service registration uses a value other than `edge-service-api`. Then the relay carries
identity fully.
