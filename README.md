# modules — a buildable security-architecture reference

A self-contained, runnable reference for a production-grade platform security
methodology. Each pattern is a real, tested module you can clone and build — not
a code dump. Patterns are drawn from production experience building a
multi-tenant credentialing platform; the platform itself is not named or exposed.

## The five-layer posture

Security is enforced structurally at every layer, deny-by-default, with no
partial implementation. Each module below is a concrete, runnable proof of one
layer.

| Layer | Concern | Module |
|---|---|---|
| 1 — Identity / AuthN | OIDC + PKCE, MFA / step-up | `edge-perimeter` *(planned)* |
| 2 — Authorization | coarse edge + fine-grained service, deny-by-default | `layered-authorization` *(planned)* |
| 3 — Secrets / config | no secret in git or image; rotation is config | *(documented in ADR-0001)* |
| 4 — Transport / runtime | perimeter, headers, actuator lockdown | `edge-perimeter` *(planned)* |
| 5 — Data | per-service DB roles, RLS, least privilege | **`tenant-isolation`** |
| 5 — Supply chain | SBOM, signing, dep-scan, base-image pin | `supply-chain` *(planned)* |
| cross-cutting | crypto strategy, agility, post-quantum roadmap | `crypto-agility` *(planned)* |

## Modules

- **`tenant-isolation`** — PostgreSQL Row-Level Security + session-bound
  `app.current_tenant`, served by a non-superuser pool identity. Includes an
  audit test that fails if the pool role can bypass RLS. *(in progress)*

## Build

Requires JDK 21 and Docker (for Testcontainers integration tests).

```bash
./gradlew build                    # build + test everything
./gradlew :tenant-isolation:test   # one module
```

## Methodology (ADRs)

Architecture Decision Records live in [`docs/adr/`](docs/adr/). Start with
[ADR-0001 — the five-layer security posture](docs/adr/0001-five-layer-security-posture.md).

## License

MIT — see [LICENSE](LICENSE).
