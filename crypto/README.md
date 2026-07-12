# Crypto

This is a stable signing API. Algorithms and providers are plug-and-play. It is the
toolkit's cryptographic-agility seam.

Call sites depend on `DocumentSigner`. Algorithms live behind `SignatureProvider` and
an immutable registry. `Ed25519` and `ECDSA P-256` ship as built-ins. Additional
providers bring their own `SignatureAlgorithm` identity without edits to the core.

## Quick Start

```bash
../gradlew :crypto:test
```

## Library Artifacts

Plain Java or custom Spring wiring:

```kotlin
implementation("io.github.joshuamatosdev.security:crypto:0.1.0-SNAPSHOT")
testImplementation("io.github.joshuamatosdev.security:crypto-testkit:0.1.0-SNAPSHOT")
```

Spring Boot auto-configuration:

```kotlin
implementation("io.github.joshuamatosdev.security:crypto-spring-boot-starter:0.1.0-SNAPSHOT")
```

Runnable consumer examples exist. See
[`examples/crypto-plain-java`](../examples/crypto-plain-java/). Also
[`examples/crypto-spring-boot`](../examples/crypto-spring-boot/).

## API Surface

| Type | Role |
|---|---|
| `DocumentSigner` | Explicit-key signing and typed verification. |
| `DefaultDocumentSigner` | Default-key signing, available only when key resolution is configured. |
| `SignedDocument` | Payload + signature + embedded public key + `alg`/`keyId` metadata. |
| `TrustAnchor` | The deployment's trusted key per id. |
| `SignatureProvider` / `SignatureProviderRegistry` | Provider seam. `JcaSignatureProviders` ships JCA implementations. |
| `KeyHandle` / `KeyHandleResolver` / `KeyIdStrategy` | Key custody seam for default-key signing. Back with KMS/HSM in production. |
| `SignatureAuditSink` / `SignatureAuditEvent` | Records every sign and verify outcome. Success or failure. |

## Integrity vs. Authenticity

`verify(SignedDocument)` proves payload integrity. It uses the **embedded** public key.
Beware a key-substitution forgery. An attacker tampers the payload. They re-sign under
an attacker-chosen key. The key id stays the same. This forgery still verifies.
Documents crossing a trust boundary differ. They must use the anchored overload:

```java
TrustAnchor anchor = TrustAnchor.pinnedKeys(Map.of("k1", trustedPublicKey));
boolean authentic = signer.verify(signed, anchor).isVerified();
```

The anchor is checked first. This happens before any signature computation. A rejection
is audited as `untrusted key`. Production can back `TrustAnchor` differently. Use KMS
public-key lookup. Or use a key directory. `pinnedKeys` compares in constant time.

## Spring Boot Starter

```yaml
crypto:
  default-algorithm: EdDSA
  default-key-id: local-ed25519-1
  providers:
    jca:
      ed25519:
        enabled: true
```

The starter always injects `DocumentSigner`. It injects `DefaultDocumentSigner` only
when app-owned key custody supplies a `KeyHandleResolver`. One opt-in is demo-only. It is
`crypto.local-ephemeral-keys.enabled`. It generates in-memory keys. It must
stay off in production. Disable the whole starter easily. Set
`crypto.enabled: false`.

## Testkit

`crypto-testkit` carries reusable contracts. Provider and signer authors reuse them.
They skip copying internal tests. `DocumentSignerContract` covers several checks. It
covers round-trip. It covers tamper rejection. It covers algorithm-relabel rejection.
It covers the anchored verify. A trusted key is accepted. A substituted key fails
closed. An unknown key id fails closed. `SignatureProviderContract` is included too. So
is `SignatureProviderRegistryContract`. Fakes support wiring tests.

## Compliance Boundary

Algorithms appear by name here. Even FIPS-approved names appear. A name is only a
name. It claims no FIPS validation. Not for any runtime provider. Not for any
deployment or environment.
Production systems own the real work. They own provider validation. They own key
custody. They own rotation policy. They own compliance review.
