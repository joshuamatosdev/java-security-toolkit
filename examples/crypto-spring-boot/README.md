# Crypto Spring Boot Example

The example uses a composite build. It includes the repository root. So it uses the
current checkout. No local Maven publication is needed. Run it from the repository
root:

```bash
./gradlew -p examples/crypto-spring-boot bootRun
```

The runner verifies integrity first. It uses the embedded key. Then it verifies
authenticity. It checks `TrustAnchor.pinnedKeys(...)`. The wiring supplies its own
keys. Never from the document under test. The example opts into ephemeral keys. These
are local ephemeral signing keys. So `DocumentSigner.sign(byte[])` runs without
external custody. Production apps should disable that opt-in. Supply a
`KeyHandleResolver` instead. Use KMS or HSM custody.
