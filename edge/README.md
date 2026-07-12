# Edge Perimeter

This is a runnable reference. It builds a BFF security edge. It has two distinct
credential planes. Browser authentication is one security chain.
Service-to-service authentication is a separate chain. It enforces deny-by-default
routing. It sets response headers. It locks down the actuator. All at one place.
Every response passes through it.

It covers Layer 1, identity and authentication, plus Layer 4, transport and runtime
hardening, in the repository's composed security posture.

## Table of Contents

- [Quick Start](#quick-start)
- [Library Artifacts](#library-artifacts)
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
../gradlew :edge:test
```

The app context boots fully offline. The OIDC provider endpoints are fictional. They
are never contacted. No client-provider `issuer-uri` discovery happens. The JWT
decoder fetches lazily. Tests authenticate with `spring-security-test` mutators.

## Library Artifacts

Plain Java or custom Spring wiring:

```kotlin
implementation("io.github.joshuamatosdev.security:edge:0.1.0-SNAPSHOT")
testImplementation("io.github.joshuamatosdev.security:edge-testkit:0.1.0-SNAPSHOT")
```

The testkit ships two contracts. One is `EdgePropertiesContract`. It proves hardened
defaults. It rejects non-loopback HTTP issuers. The other is `CorsAllowListContract`.
It covers credentialed CORS. It refuses wildcard origins. It refuses opaque `null`
origins. It refuses non-loopback HTTP origins. Implement them in your test suite. They prove your
deployment policy. They run against the startup guards. The module runs both contracts
itself.

Spring Boot auto-configuration:

```kotlin
implementation("io.github.joshuamatosdev.security:edge-spring-boot-starter:0.1.0-SNAPSHOT")
```

The starter imports the perimeter configuration. It is the reference WebFlux setup.
This happens when `edge.enabled` is true. It also applies when absent. Disable
it with:

```yaml
edge:
  enabled: false
```

## What It Demonstrates

- Two ordered `SecurityWebFilterChain`s. One per credential plane.
- Deny-by-default routing. A narrow role exception comes first. It sits before a broad
  gate.
- A browser/service credential-isolation filter runs. It strips a smuggled bearer
  token.
- OIDC Authorization-Code plus PKCE. This serves a public client. The generated login
  page is suppressed.
- Issuer and audience validation runs. It checks browser ID tokens. It checks service
  JWTs. No startup-time discovery is needed.
- A credentialed CORS allow-list. It refuses wildcard and opaque origins. Malformed
  origins too, at startup.
- CSRF double-submit on the browser plane. The stateless service plane disables CSRF.
- OWASP security headers on every response. HSTS is policy-driven.
- Actuator lockdown in two independent layers. Exposure config plus a deny rule.

## The Two Credential Planes

| Plane | Matcher | Credential | Session | CSRF | CORS |
|---|---|---|---|---|---|
| Service | `/api/service/**` | bearer JWT | none | disabled | none |
| Browser | everything else | session cookie (OIDC login) | cookie | double-submit | allow-list |

The service chain registers first. It uses a `securityMatcher`. So it owns only its
paths. Everything else hits the browser chain. The browser plane strips bearer tokens.
It also logs them. This is `BrowserCredentialIsolationFilter`. The service plane keeps
the token. That token is its whole credential.

The `401`-vs-`403` split has meaning. It marks the authentication-vs-authorization
boundary. No token returns `401`. It carries a `Bearer` challenge. A valid token can
still fail. Missing the required role returns `403`.

## Route Map

The browser route map is deny-by-default. Every browser surface is listed explicitly.
The map ends in `anyExchange().denyAll()`. Narrow exceptions come first. They sit
before broad gates. Matching is first-match-wins:

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

`SecurityHeadersFilter` runs at highest precedence. It writes the OWASP header set.
This happens in `beforeCommit`. So headers reach Spring Security responses. That
includes login redirects and 403s. Not just proxied responses. HSTS is the one
conditional header. Set `edge.hsts.unconditional=true` to always emit it. Use this
where TLS terminates upstream. Otherwise it needs HTTPS. Then `X-Forwarded-Proto` must
report HTTPS.

## Configuration

Only deployment policy is configurable. The structural rules are code.

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

The shipped default profile is hardened. It sets Secure cookies. It uses unconditional
HSTS. Plain-HTTP local runs need another profile. Activate the `local` profile. Use
`--spring.profiles.active=local`. It relaxes two settings together. These are
`cookie.secure` and `hsts.unconditional`. Never one without the other.

## Testing

```bash
../gradlew :edge:test --tests "*RouteAuthorizationTest"
../gradlew :edge:test --tests "*ServiceApiAuthorizationTest"
```

`WebTestClient` tests cover much ground. They cover route authorization. They cover the
service plane. They cover CSRF and CORS preflight. They cover header presence. Fast
unit tests cover more. They cover the HSTS conditional matrix. They cover the
credential-isolation filter. Every rule has observable proof. Observe a status code or
header. Never by reading the configuration.
