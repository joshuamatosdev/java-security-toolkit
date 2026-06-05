# Crypto Agility Spring Boot Example

Run from the repository root. The example includes the repository root as a
composite build, so it uses the current checkout and does not require a local
Maven publication:

```bash
./gradlew -p examples/crypto-agility-spring-boot bootRun
```

The starter auto-configures local JCA Ed25519, a default key id, and `DocumentSigner`. Replace the
local key resolver/provider with KMS or HSM custody before production use.
