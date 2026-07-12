# Authorization Testkit

Reusable policy contracts for [`authorization`](../authorization/). Adopters provide an
`AuthorizationPolicy`; the contract verifies tenant mismatch, deny-overrides, organization scope,
team scope, and action-specific decisions.

Depend on this module in test scope and implement `AuthorizationPolicyContract`.

Verify with `./gradlew :authorization-testkit:test`.
