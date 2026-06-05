# Crypto Agility Spring Boot Example

Run from the repository root after publishing the library locally:

```bash
./gradlew publishToMavenLocal
./gradlew -p examples/crypto-agility-spring-boot bootRun
```

The starter auto-configures local JCA Ed25519, a default key id, and `DocumentSigner`. Replace the
local key resolver/provider with KMS or HSM custody before production use.
