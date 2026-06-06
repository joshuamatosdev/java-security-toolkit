# Crypto Agility

Crypto-agility is now a small production-consumable Java library family:

- `crypto-agility-core` - plain Java 21 library, no Spring dependency.
- `crypto-agility-spring-boot-starter` - optional Spring Boot auto-configuration.
- `crypto-agility-testkit` - reusable contract tests and fakes for adopters and provider authors.
- `crypto-agility` - compatibility artifact that depends on `crypto-agility-core`.

Stable integration contracts live in `io.github.joshuamatosdev.security.crypto.api`.
Concrete local JCA providers live in `io.github.joshuamatosdev.security.crypto.jca` and are
replaceable. The decision record remains [ADR-0006](../docs/adr/0006-crypto-agility-provider-seam.md).

## Install

Publish locally from the repository root:

```bash
./gradlew build publishToMavenLocal
```

Plain Java consumers:

```kotlin
dependencies {
    implementation("io.github.joshuamatosdev.security:crypto-agility-core:0.1.0-SNAPSHOT")
}
```

Spring Boot consumers:

```kotlin
dependencies {
    implementation("io.github.joshuamatosdev.security:crypto-agility-spring-boot-starter:0.1.0-SNAPSHOT")
}
```

Provider implementers can add the reusable contracts:

```kotlin
dependencies {
    testImplementation("io.github.joshuamatosdev.security:crypto-agility-testkit:0.1.0-SNAPSHOT")
}
```

## Plain Java Setup

```java
import io.github.joshuamatosdev.security.crypto.api.DocumentSigner;
import io.github.joshuamatosdev.security.crypto.api.KeyHandle;
import io.github.joshuamatosdev.security.crypto.api.SignatureAlgorithm;
import io.github.joshuamatosdev.security.crypto.api.SignatureProviderRegistry;
import io.github.joshuamatosdev.security.crypto.api.SignedDocument;
import io.github.joshuamatosdev.security.crypto.jca.JcaSignatureProviders;
import java.nio.charset.StandardCharsets;
import java.util.List;

var registry = new SignatureProviderRegistry(List.of(JcaSignatureProviders.ed25519()));
var signer = new DocumentSigner(registry);
KeyHandle key = registry.resolve(SignatureAlgorithm.ED25519).generateKey("local-ed25519-1");

SignedDocument signed = signer.sign(key, "document".getBytes(StandardCharsets.UTF_8));
boolean verified = signer.verify(signed);
```

The shipped JCA providers are `ed25519()`, `ecdsaP256()`, and
`postQuantumPlaceholder()`. The placeholder reports `ML-DSA-44` but signs with an Ed25519 stand-in;
it is an agility demo slot, not post-quantum protection.

## Spring Boot Setup

The starter auto-registers a `DocumentSigner` when enabled. Defaults:

```yaml
glyptodon:
  crypto:
    enabled: true
    default-algorithm: ED25519
    default-key-id: local-ed25519-1
    providers:
      jca:
        ed25519:
          enabled: true
        ecdsa-p256:
          enabled: false
        ml-dsa-44-placeholder:
          enabled: false
```

Inject and use:

```java
@Service
final class SigningService {
    private final DocumentSigner signer;

    SigningService(DocumentSigner signer) {
        this.signer = signer;
    }

    SignedDocument sign(byte[] payload) {
        return signer.sign(payload);
    }
}
```

Startup fails if the configured default algorithm has no provider or if duplicate provider beans
report the same algorithm.

## Adding A Provider

Implement `SignatureProvider` and return `KeyHandle` instances that hide private material:

```java
final class KmsSignatureProvider implements SignatureProvider {
    public SignatureAlgorithm algorithm() { return SignatureAlgorithm.ED25519; }
    public KeyHandle generateKey(String keyId) {
        throw new UnsupportedOperationException("wire to KMS custody");
    }
    public boolean verify(byte[] publicKey, byte[] payload, byte[] signature) {
        throw new UnsupportedOperationException("wire to KMS verification");
    }
}
```

Run the testkit contract:

```java
class KmsSignatureProviderContractTest implements SignatureProviderContract {
    public SignatureProvider provider() {
        return new KmsSignatureProvider();
    }
}
```

## Key Custody Integration

The local JCA provider stores software keys in process and is suitable for examples and local
integration tests. Production deployments should replace `KeyHandleResolver` and provider
implementations with KMS, HSM, hardware-backed wallet custody, or another approved custody boundary.

`DocumentSigner.sign(byte[])` uses:

- `SignatureAlgorithm` - configured default algorithm.
- `KeyIdStrategy` - selects the active key id for the algorithm.
- `KeyHandleResolver` - resolves the handle for that algorithm/key id.

## Rotation Strategy

Use versioned key ids. A rotation creates a new handle under a new `keyId`, updates `KeyIdStrategy`
for new signatures, and keeps old public keys/verifiers available for retained signed documents.
Do not reuse a key id for different private material.

## FIPS And Compliance Notes

`SignatureAlgorithm.fipsApproved()` describes the algorithm identity only. It does not prove the
runtime provider is a validated cryptographic module. FIPS posture requires validating the concrete
provider, module boundary, mode, operating environment, key custody, and operational controls.

The `ML_DSA_44` placeholder is deliberately loud: it is an Ed25519-backed migration slot and must
not be treated as ML-DSA conformance or quantum resistance.

## Threat Model And Non-Goals

This library keeps call sites algorithm-agnostic and signs envelope metadata so tampering with
payload, algorithm, key id, public key, or signature fails verification.

It does not:

- establish signer authenticity when a document carries its own public key
- manage trust anchors or certificate chains
- store or rotate production keys
- certify FIPS/CMVP compliance
- implement real ML-DSA in Java 21
- replace protocol-specific JOSE, COSE, VC, or mdoc validation

## Examples

Runnable consumer examples live under:

- `../examples/crypto-agility-plain-java`
- `../examples/crypto-agility-spring-boot`
