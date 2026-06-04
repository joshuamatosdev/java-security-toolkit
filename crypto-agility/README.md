# Crypto Agility

A runnable reference for cryptographic agility: every algorithm-specific decision sits behind one
provider interface, providers are resolved from a registry keyed by algorithm, and keys are
referenced by versioned handles that sign without ever exposing their private material. The result
is a signing call site that names no algorithm — so swapping Ed25519 for ECDSA P-256, or migrating
to a post-quantum algorithm, is a configuration change, not a code change.

It covers the cross-cutting crypto-strategy layer of the
[five-layer posture](../docs/adr/0001-five-layer-security-posture.md). The decision record is
[ADR-0006](../docs/adr/0006-crypto-agility-provider-seam.md).

## Table of Contents

- [Quick Start](#quick-start)
- [What It Demonstrates](#what-it-demonstrates)
- [The Agility Property](#the-agility-property)
- [The Post-Quantum Slot](#the-post-quantum-slot)
- [Testing](#testing)

## Quick Start

Requirements:

- JDK 21 (no Docker, no network — every algorithm is a JDK platform primitive)

```bash
../gradlew :crypto-agility:test
```

## What It Demonstrates

| Concept | Where |
|---|---|
| Algorithm registry | `registry/SignatureAlgorithm` — the single authority for algorithm + `alg` wire id + family |
| Provider seam | `provider/SignatureProvider` — `algorithm()` + `generateKey` + `verify`; all algorithm logic lives here |
| Algorithm → provider dispatch | `registry/SignatureProviderRegistry` — immutable, rejects duplicate algorithms |
| Versioned key handle | `key/KeyHandle` — `keyId` + `algorithm` + `publicKey` + `sign`; private material never exposed |
| Algorithm-agnostic call site | `seal/DocumentSigner` — seals and verifies, names no algorithm |
| Post-quantum slot | `provider/SignatureProviders.postQuantumPlaceholder()` — `ML-DSA-44`, reserved and exercised |

## The Agility Property

`DocumentSigner` is the call site, and these two method bodies serve every algorithm:

```java
SignedDocument seal(KeyHandle key, byte[] document) {
    byte[] signature = key.sign(document);                       // the handle knows its algorithm
    return new SignedDocument(key.algorithm().joseAlg(), key.keyId(),
                              key.publicKey(), document, signature);
}

boolean verify(SignedDocument document) {
    SignatureAlgorithm algorithm = SignatureAlgorithm.fromJoseAlg(document.alg());
    return registry.resolve(algorithm)                           // the registry picks the provider
                   .verify(document.publicKey(), document.payload(), document.signature());
}
```

Neither names an algorithm. `DocumentSignerTest` parameterises over **every** registered algorithm
through this identical call site and asserts each round-trips — the falsifiable form of "an
algorithm swap leaves call sites unchanged."

## The Post-Quantum Slot

ML-DSA-44 (FIPS 204) is the migration target, and it is **not** in the JDK 21 platform. The slot
exists anyway: `SignatureAlgorithm.ML_DSA_44` and `SignatureProviders.postQuantumPlaceholder()`
report the `ML-DSA-44` wire identifier and run the full registry / handle / call-site path with a
**stand-in Ed25519 primitive**. It produces and verifies real signatures end-to-end; only the
underlying primitive is a stand-in — this module is **not** ML-DSA conformance or quantum
resistance.

The real migration swaps the placeholder primitive for `Signature.getInstance("ML-DSA")` (JDK 24)
or a BouncyCastle PQC provider, with no change to the interface, the registry, or any call site —
see the activation procedure in [ADR-0006](../docs/adr/0006-crypto-agility-provider-seam.md).

## Testing

```bash
../gradlew :crypto-agility:test --tests "*DocumentSignerTest"          # the agility property
../gradlew :crypto-agility:test --tests "*JcaSignatureProviderTest"    # per-algorithm round-trips
../gradlew :crypto-agility:test --tests "*SignatureProviderRegistryTest"
```

The agility claim is proven by driving one call site across every algorithm, not by reading the
interface.
