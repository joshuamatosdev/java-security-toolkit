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

Template: [TEMPLATE.md](TEMPLATE.md).

Shared terminology is defined in the [module glossary](../GLOSSARY.md).
