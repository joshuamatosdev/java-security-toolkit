# Crypto Plain Java Example

The example uses a composite build. It includes the repository root. So it uses the
current checkout. No local Maven publication is needed. Run it from the repository
root:

```bash
./gradlew -p examples/crypto-plain-java run
```

The example signs a payload. It verifies integrity next. It uses the embedded key.
Then it verifies authenticity. It checks `TrustAnchor.pinnedKeys(...)`. It is the
verifier's own opinion. It picks which key may speak. For a given key id. This example
uses one provider. It is local JCA Ed25519 only. Replace it before production use. Use
a KMS/HSM-backed `SignatureProvider`. And a matching `KeyHandle`.
