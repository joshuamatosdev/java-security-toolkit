# Crypto Agility Spring Boot Example

Run from the repository root. The example includes the repository root as a
composite build, so it uses the current checkout and does not require a local
Maven publication:

```bash
./gradlew -p examples/crypto-spring-boot bootRun
```

The example opts into local ephemeral signing keys so `DocumentSigner.sign(byte[])` can run without
external custody. Production applications should leave that opt-in disabled and supply a
`KeyHandleResolver` backed by KMS or HSM custody.
