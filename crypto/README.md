# Crypto

A stable signing API with replaceable algorithms and providers — the
cryptographic-agility seam of the toolkit.

Call sites depend on `DocumentSigner`; algorithms (`Ed25519`, `ECDSA P-256`, a
reserved post-quantum slot) and providers live behind `SignatureProvider` and a
registry, so an algorithm migration changes configuration and provider wiring,
never the call sites. The decision record is
[ADR-0006](../docs/adr/0006-crypto-provider-seam.md).

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

Runnable consumer examples: [`examples/crypto-plain-java`](../examples/crypto-plain-java/)
and [`examples/crypto-spring-boot`](../examples/crypto-spring-boot/).

## API Surface

| Type | Role |
|---|---|
| `DocumentSigner` | Sign and verify; the only type application code should call. |
| `SignedDocument` | Payload + signature + embedded public key + `alg`/`keyId` metadata. |
| `TrustAnchor` | The deployment's opinion of which public key may speak for a key id. |
| `SignatureProvider` / `SignatureProviderRegistry` | The provider seam; `JcaSignatureProviders` ships the JCA implementations. |
| `KeyHandle` / `KeyHandleResolver` / `KeyIdStrategy` | Key custody seam for default-key signing (back with KMS/HSM in production). |
| `SignatureAuditSink` / `SignatureAuditEvent` | Every sign and verify outcome — success or failure — is recorded. |

## Integrity vs. Authenticity

`verify(SignedDocument)` proves payload integrity under the public key
**embedded in the document** — a key-substitution forgery (tampered payload
re-signed under an attacker-chosen key, embedded under the same key id) still
verifies. Documents that cross a trust boundary must use the anchored overload:

```java
TrustAnchor anchor = TrustAnchor.pinnedKeys(Map.of("k1", trustedPublicKey));
boolean authentic = signer.verify(signed, anchor);   // fails closed on an untrusted key
```

The anchor is consulted before any signature computation and the rejection is
audited as `untrusted key`. Production deployments can back `TrustAnchor` with
KMS public-key lookup or a key directory; `pinnedKeys` compares in constant
time.

## Spring Boot Starter

```yaml
bulwark:
  crypto:
    default-algorithm: ED25519
    default-key-id: local-ed25519-1
    providers:
      jca:
        ed25519:
          enabled: true
```

The starter injects `DocumentSigner`. Default-key signing requires app-owned
key custody (`KeyHandleResolver`); `bulwark.crypto.local-ephemeral-keys.enabled`
is a demo-only opt-in that generates in-memory keys and must stay off in
production. Disable the whole starter with `bulwark.crypto.enabled: false`.

## Testkit

`crypto-testkit` carries reusable contracts so provider and signer
implementations do not copy internal tests: `DocumentSignerContract`
(round-trip, tamper rejection, algorithm-relabel rejection, and the anchored
verify — trusted key accepted, substituted key and unknown key id fail closed),
`SignatureProviderContract`, and `SignatureProviderRegistryContract`, plus
fakes for wiring tests.

## Compliance Boundary

A listed algorithm identity — including a FIPS-approved algorithm name — is not
a claim that any runtime provider, deployment, or environment is FIPS-validated.
Production systems own provider validation, key custody, rotation policy, and
compliance review.
