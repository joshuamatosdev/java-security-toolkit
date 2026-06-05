# Edge Perimeter

A runnable reference for a backend-for-frontend (BFF) security edge with two
distinct credential planes. The module keeps browser authentication and
service-to-service authentication as separate security chains, and enforces
deny-by-default routing, response headers, and actuator lockdown at the one place
every response passes through.

It covers Layer 1 (identity / authentication) and Layer 4 (transport / runtime
hardening) in the
[five-layer posture](../docs/adr/0001-five-layer-security-posture.md). The decision
record is [ADR-0004](../docs/adr/0004-edge-perimeter-dual-plane.md).

## Table of Contents

- [Quick Start](#quick-start)
- [What It Demonstrates](#what-it-demonstrates)
- [The Two Credential Planes](#the-two-credential-planes)
- [Route Map](#route-map)
- [Transport Hardening](#transport-hardening)
- [Configuration](#configuration)
- [Testing](#testing)

## Quick Start

Requirements:

- JDK 21 (no database, no Docker)

Run the module tests:

```bash
../gradlew :edge-perimeter:test
```

The application context boots fully offline: the OIDC provider endpoints are
fictional and never contacted (no client-provider `issuer-uri` discovery; the JWT
decoder fetches lazily), and tests authenticate with `spring-security-test` mutators.

## What It Demonstrates

- Two ordered `SecurityWebFilterChain`s, one per credential plane.
- Deny-by-default routing with a narrow role exception ordered before a broad gate.
- A browser/service credential-isolation filter that strips a smuggled bearer token.
- OIDC Authorization-Code + PKCE for a public client, with the generated login page
  suppressed.
- Issuer and audience validation for browser ID tokens and service JWTs without
  startup-time discovery.
- A credentialed CORS allow-list that refuses wildcard, opaque, or malformed origins at startup.
- CSRF double-submit on the browser plane; CSRF disabled on the stateless service
  plane.
- OWASP security headers on every response, with policy-driven HSTS.
- Actuator lockdown in two independent layers (exposure config + deny rule).

## The Two Credential Planes

| Plane | Matcher | Credential | Session | CSRF | CORS |
|---|---|---|---|---|---|
| Service | `/api/service/**` | bearer JWT | none | disabled | none |
| Browser | everything else | session cookie (OIDC login) | cookie | double-submit | allow-list |

The service chain is registered first with a `securityMatcher`, so it owns only its
paths; everything else falls through to the browser chain. A bearer token presented
on the browser plane is stripped and logged
(`BrowserCredentialIsolationFilter`); the service plane keeps it because that is its
whole credential.

The service plane's `401`-vs-`403` split is the authentication-vs-authorization
boundary: no token is `401` (with a `Bearer` challenge), a valid token without the
required role is `403`.

## Route Map

The browser route map is deny-by-default — every browser surface is listed
explicitly and the map ends in `anyExchange().denyAll()`. Narrow exceptions come
before the broad gates they sit under, because matching is first-match-wins:

```
/api/public/**            permitAll
/actuator/health/**       permitAll
/actuator/info            permitAll
/actuator/**              denyAll
/api/documents/**         authenticated
/api/admin/audit-export   ROLE_auditor or ROLE_admin     # narrow, first
/api/admin/**             ROLE_admin                      # broad, second
anyExchange               denyAll
```

## Transport Hardening

`SecurityHeadersFilter` runs at highest precedence and writes the OWASP header set in
`beforeCommit`, so the headers reach responses Spring Security generates (login
redirects, 403s), not just proxied ones. HSTS is the one conditional header: emitted
unconditionally when `edge.hsts.unconditional=true` (where TLS terminates upstream),
otherwise only when `X-Forwarded-Proto` reports HTTPS.

## Configuration

Only deployment policy is configurable; the structural rules are code.

```yaml
edge:
  identity:
    issuer-uri: https://idp.acme.example
  service-jwt:
    audiences:
      - edge-service-api
  cors:
    allowed-origins:
      - https://app.acme.example   # wildcard/opaque origins are rejected at startup
  cookie:
    secure: true                   # hardened default; cookies carry Secure
  hsts:
    unconditional: true            # emitted on every response
```

The shipped default profile is hardened: Secure cookies under unconditional HSTS. Plain-HTTP
local runs activate the `local` profile (`--spring.profiles.active=local`), which relaxes
`cookie.secure` and `hsts.unconditional` together — never one without the other.

## Testing

```bash
../gradlew :edge-perimeter:test --tests "*RouteAuthorizationTest"
../gradlew :edge-perimeter:test --tests "*ServiceApiAuthorizationTest"
```

`WebTestClient` tests cover route authorization, the service plane, CSRF, CORS
preflight, and header presence; fast unit tests cover the HSTS conditional matrix and
the credential-isolation filter. Every rule is proven by an observable status code or
header, not by reading the configuration.
