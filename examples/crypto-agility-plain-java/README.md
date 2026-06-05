# Crypto Agility Plain Java Example

Run from the repository root after publishing the library locally:

```bash
./gradlew publishToMavenLocal
./gradlew -p examples/crypto-agility-plain-java run
```

This example uses the local JCA Ed25519 provider only. Replace it with a KMS/HSM-backed
`SignatureProvider` and `KeyHandle` before production use.
