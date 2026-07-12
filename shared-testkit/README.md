# Shared Testkit

Reusable contracts for the typed identifiers in [`shared`](../shared/). They verify canonical UUID
parsing, type separation, equality, and rejection of malformed identifier text.

Depend on this module in test scope and implement the identifier contract for an adopter type.

Verify with `./gradlew :shared-testkit:test`.
