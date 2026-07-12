# Crypto Testkit

Reusable contracts for [`crypto`](../crypto/) provider authors and signer integrations. The
contracts cover sign/verify round trips, wrong-key rejection, tamper rejection, envelope behavior,
and typed verification failures.

Depend on this module in test scope and implement the provider or signer contract.

Verify with `./gradlew :crypto-testkit:test`.
