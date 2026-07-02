# Architecture Decision Records

Each ADR captures one decision: context, the decision, rationale, and the
tradeoffs rejected. They are the methodology behind the modules.

| ADR | Title | Module |
|---|---|---|
| [0001](0001-five-layer-security-posture.md) | Five-layer security posture | (spine) |
| [0002](0002-tenant-isolation-rls-session-binding.md) | Tenant isolation: RLS + session binding | `tenant-isolation` |
| [0003](0003-layered-authorization.md) | Layered authorization: typed principal, scoped policy, deny-by-default | `layered-authorization` |
| [0004](0004-edge-perimeter-dual-plane.md) | Edge perimeter: dual credential planes, deny-by-default routing | `edge-perimeter` |
| [0005](0005-supply-chain-trust-horizon.md) | Supply-chain trust horizon: pin, verify, enumerate build inputs | `supply-chain` |
| [0006](0006-crypto-agility-provider-seam.md) | Cryptographic agility: one provider seam, a registry, a reserved post-quantum slot | `crypto-agility` |
| [0007](0007-organization-scope-within-tenant-isolation.md) | Organization scope within tenant isolation: co-equal binding dimension, second signed claim, RESTRICTIVE cap | `tenant-isolation` |
| [0008](0008-entitlement-cross-tenant-read-grants.md) | Entitlement-based cross-tenant read grants: explicit grant ledger, SELECT-only policy, platform-plane administration | `tenant-isolation` |

Template: [TEMPLATE.md](TEMPLATE.md).

Shared terminology is defined in the [module glossary](../GLOSSARY.md).
