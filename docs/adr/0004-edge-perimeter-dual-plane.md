# ADR-0004: Edge Perimeter with Two Credential Planes, Deny-by-Default Routing, and Browser/Service Isolation

- **Status:** Accepted
- **Date:** 2026-06-03

## Context

The edge is where two of the five posture layers meet: **identity / authentication**
(Layer 1 — how a caller proves who they are) and **transport / runtime hardening**
(Layer 4 — perimeter, response headers, actuator exposure). A backend-for-frontend
(BFF) gateway owns this boundary: it terminates the browser's authenticated session,
relays calls to the backend, and is the one place security headers and the route map
are enforced for *every* response, including ones the framework generates itself.

The central trap is treating all callers the same. Two structurally different
credentials arrive at one edge:

- A **browser** authenticates with a session cookie minted by an interactive OIDC
  login. Cookies are sent automatically by the browser, so this plane needs CSRF
  protection and a credentialed CORS allow-list, and it must never expose a bearer
  token to client JavaScript.
- A **service** (machine-to-machine) authenticates with a bearer JWT on every
  request. This plane is stateless: no cookie, so no CSRF surface and no browser to
  forge from; no CORS surface because there is no browser origin.

If a single security chain serves both, the planes blur. The most dangerous blur is
a **browser-supplied `Authorization` header**: a hostile script that can set one
would smuggle a service identity through the session boundary. The other traps are
well known and each fails silently:

- **CORS `*` with credentials** — a wildcard origin plus `allowCredentials` lets any
  website script authenticated requests against the BFF.
- **No CSRF on the cookie plane** — a third-party page can ride the session cookie.
- **Authorization-Code without PKCE for a public client** — an intercepted code is
  redeemable by anyone holding the redirect URI.
- **Actuator exposure** — `/actuator/env`, `/actuator/heapdump` leak secrets and
  memory if reachable.
- **A generated login page** — Spring's default OAuth2 login page leaks the client
  registration id and confirms the IdP backend.
- **HSTS suppressed by a stripped proxy header** — if HSTS is emitted only when
  `X-Forwarded-Proto` says HTTPS, a misclassified proxy that drops the header
  silently downgrades transport security.

## Decision

### Two ordered security chains, one per credential plane

Split the edge into two `SecurityWebFilterChain`s. The service chain is registered
first with a path matcher so it owns only its surface; everything else falls through
to the browser chain.

```
order 1  serviceApiSecurityFilterChain   securityMatcher /api/service/**
           → OAuth2 resource server (bearer JWT), roles claim → ROLE_*
           → stateless: CSRF disabled, no form/basic login
           → 401 (no/invalid token) vs 403 (valid token, missing role)

order 2  browserSecurityFilterChain      (everything else)
           → OIDC Authorization-Code + PKCE login, session cookie
           → CSRF double-submit cookie, credentialed CORS allow-list
           → deny-by-default route map, security headers, actuator lockdown
```

The planes are kept disjoint by a top-of-chain filter that **strips any inbound
`Authorization` header on the browser plane** (and logs it at WARN as an anomaly) but
leaves it untouched on `/api/service/**`, whose contract is to accept bearer tokens.

### Deny-by-default routing, narrow exception before broad gate

The browser route map ends in `anyExchange().denyAll()` with no implicit
authenticated catch-all. Ordinary browser endpoints, such as `/api/documents`, are
registered explicitly before that fallback. Within the explicit map, a **narrow
exception is registered before the broad gate it sits under**, because Spring
Security evaluates matchers first-match-wins:

```
/api/admin/audit-export   →  hasAnyAuthority(ROLE_auditor, ROLE_admin)   // narrow, first
/api/admin/**             →  hasAnyAuthority(ROLE_admin)                  // broad, second
```

Registered in the other order, an auditor hitting `/api/admin/audit-export` would
match the broad admin rule, be denied, and never reach its own exception.

### Actuator lockdown in two independent layers

Exposure is narrowed to `health,info` in configuration **and** the route map permits
`/actuator/health/**` + `/actuator/info` then `denyAll()` on `/actuator/**`. An
endpoint accidentally added to the exposure list is still unreachable through the
deny rule.

### PKCE on every authorization request; no generated login page

The BFF is a public OAuth2 client (no secret), so every authorization request carries
a SHA-256 `code_challenge`; an intercepted code is useless without the per-request
verifier the BFF never transmits. The generated login page is suppressed by pointing
`loginPage` at the client's authorization endpoint, so the edge leaks no
client-registration identity — the SPA owns all login UX.

### Credentialed CORS allow-list that refuses `*`

CORS is credentialed (the SPA sends the cookie and the XSRF echo header) and the
configuration **fails at startup** if `*` appears in the origin list. The allowed
header set is kept minimal.

### Security headers on every response, with deliberate HSTS policy

A `WebFilter` at highest precedence writes the OWASP header set in `beforeCommit`, so
the headers reach responses Spring Security generates (login redirects, 403s), not
just proxied ones. HSTS emission is policy-driven: emitted unconditionally where TLS
terminates upstream (so a stripped `X-Forwarded-Proto` cannot suppress it), and
proto-conditional otherwise so plain-HTTP local runs do not pin browsers to TLS.

### ID-token algorithm pinned to RS256

A drift guard forces the OIDC ID-token decoder to accept only RS256 even if provider
metadata later advertised a weaker algorithm.

## Rationale

| Alternative | Reason rejected |
|---|---|
| One security chain for browser and service | The planes need opposite CSRF/CORS/session posture; one chain forces a wrong default on one of them and invites bearer-on-browser smuggling. |
| Trust a browser-supplied `Authorization` header | Lets a hostile script present a service identity through the session boundary; the browser's credential is the cookie. |
| Broad admin rule before the narrow exception | First-match-wins means the broad rule shadows the exception; the auditor never reaches its grant. |
| Actuator locked by exposure config alone | One mis-added endpoint becomes reachable; the deny rule is the backstop. |
| Authorization-Code without PKCE | A public client cannot prove possession of the code; an intercepted code is redeemable. |
| CORS `*` with credentials | Any origin can drive authenticated requests; credentialed CORS must enumerate origins. |
| Generated OAuth2 login page | Leaks the client-registration id and confirms the IdP; the SPA owns login UX. |
| HSTS only when `X-Forwarded-Proto=https` | A stripped/misclassified proxy header silently downgrades transport security. |

## Consequences

- A new endpoint is classified by plane: under `/api/service/**` it is bearer-only
  and stateless; elsewhere it is session-authenticated and inherits CSRF, CORS, and
  the deny-by-default route map. There is no third, ambiguous place.
- Every route-authorization rule, header, and the CORS allow-list is provable with a
  `WebTestClient` test and the credential-isolation and HSTS logic with fast unit
  tests; the `401`-vs-`403` split makes the authn-vs-authz boundary observable.
- This module proves the perimeter contract with plain Spring WebFlux + Spring
  Security. A production BFF adds an outbound routing layer (e.g. Spring Cloud
  Gateway) with a per-route token-relay filter; that hop does not change the edge
  rules decided here.
- Configuration carries only deployment policy (allowed origins, cookie-secure, HSTS
  mode). The structural rules — plane separation, deny-by-default, narrow-before-broad
  — are code, so they cannot be weakened by a config change.
