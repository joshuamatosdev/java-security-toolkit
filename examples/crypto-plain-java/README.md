# Crypto Agility Plain Java Example

Run from the repository root. The example includes the repository root as a
composite build, so it uses the current checkout and does not require a local
Maven publication:

```bash
./gradlew -p examples/crypto-plain-java run
```

This example uses the local JCA Ed25519 provider only. Replace it with a KMS/HSM-backed
`SignatureProvider` and `KeyHandle` before production use.
