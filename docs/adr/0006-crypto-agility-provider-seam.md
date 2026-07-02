# ADR-0006: Cryptographic Agility — One Provider Seam, a Registry, and a Reserved Post-Quantum Slot

- **Status:** Accepted
- **Date:** 2026-06-03

## Context

A signing algorithm is a decision that outlives the code that uses it. Ed25519 and ECDSA P-256 are
sound today; a cryptanalytic break, a FIPS deprecation, or the arrival of a scalable quantum
computer turns any one of them into a liability on a deadline not of the deployment's choosing. When
that day comes, the cost of migration is decided years earlier, by how the signing was written:

- If call sites name an algorithm — `Signature.getInstance("Ed25519")`, an `alg` string literal, a
  raw key passed as bytes — then every one of them is an edit, a review, and a regression risk, and
  the migration is a program, not a configuration change.
- If call sites name an *abstraction* — "sign with this key", "verify this document" — and the
  algorithm is resolved from a registry behind one interface, then adding or swapping an algorithm
  is a new provider and a registry entry, and no signing or verifying code changes.

The platform this showcase is drawn from already chose the second shape. Its `JwsSignerPort`
exposes `algorithm()` + `sign`/`verify` and is injected by qualifier, so the VC encoder stamps
`header.put("alg", signer.algorithm())` without knowing which signer it received; the wallet's
`KeyAlgorithm` enum is the single algorithm authority, and `HardwareKeyHandle` references key
material by a versioned `keyId` and signs without ever exposing the private key. This module
distils those three patterns into one runnable, framework-free demonstration.

Post-quantum signatures sharpen the point. ML-DSA (FIPS 204) is the migration target, but it is not
in the JDK 21 platform. A design is only agile if it can absorb that algorithm without disturbing
the call sites — so the seam must be provable against an algorithm that is *not yet really there*.

## Decision

Put every algorithm-specific decision behind one provider seam, resolve providers from a registry
keyed by algorithm, reference keys by versioned handles that sign without exposing material, and
reserve a real, exercised slot for the post-quantum algorithm.

### One provider interface

`SignatureProvider` (`algorithm()`, `generateKey(keyId)`, `verify(publicKey, payload, signature)`)
is the only place algorithm-specific logic lives. A provider is bound to exactly one
`SignatureAlgorithm`. Callers depend on the interface, never a concrete provider. The stable
library surface now lives under `io.github.joshuamatosdev.security.crypto.api`; JCA-backed classes
live under `io.github.joshuamatosdev.security.crypto.jca`.

### A registry, not a switch

`SignatureProviderRegistry` maps each `SignatureAlgorithm` to its provider, is immutable after
construction, and rejects two providers for the same algorithm. Algorithm selection drives provider
selection (`resolve(algorithm)`); the policy decision "which algorithm" is data the registry holds,
not a branch in a call site.

### Versioned key handles that never expose material

`KeyHandle` (`keyId`, `algorithm`, `publicKey`, `sign`) is a versioned reference to a key. It signs
with material bound internally and returns only the public key; rotation means a new handle under a
new `keyId`. No call site holds, copies, or passes a private key.

### One call site, every algorithm

`DocumentSigner.sign`/`seal`/`verify` is the demonstration: it reads the algorithm off the handle when
sealing and resolves the provider off the document's `alg` label when verifying, and it names no
algorithm. *(Amended: the `seal` alias was later removed — one entry point per operation; `sign` is
the single signing call site. A trust-anchored `verify(document, trustAnchor)` overload was added so
signer authenticity, not only payload integrity, is part of the demonstrated surface.)* The same two method bodies serve Ed25519, ECDSA P-256, and the post-quantum slot. The
agility test parameterises over every algorithm through that single call site.

### A reserved, exercised post-quantum slot

`SignatureAlgorithm.ML_DSA_44` and `JcaSignatureProviders.postQuantumPlaceholder()` exist now. The
placeholder reports the `ML-DSA-44` wire identifier and exercises the full registry / handle /
call-site path with a **stand-in Ed25519 primitive**, because ML-DSA-44 is absent from JDK 21. It
produces and verifies real signatures end-to-end; only the underlying primitive is a stand-in.

## Rationale

| Alternative | Reason rejected |
|---|---|
| Name the algorithm at each call site | Every migration becomes an edit-and-review of every signing path; the cost is paid under time pressure, exactly when error is most likely. |
| One `JcaSignatureProvider` with an `if/switch` on algorithm | Adding an algorithm edits the shared method; the registry makes a provider additive and isolates each algorithm's failure modes. |
| Pass raw key bytes / `PrivateKey` to a signing function | Material spreads across call sites and logs; the handle keeps signing capability without ever surfacing the private key, and makes rotation a handle swap. |
| Wait for a real ML-DSA provider before reserving the slot | The agility claim is precisely that a not-yet-present algorithm slots in unchanged; proving it requires the slot to exist now. The stand-in keeps the module dependency-light and offline while exercising the seam. |
| Ship a real ML-DSA via BouncyCastle PQC now | Pulls a heavyweight dependency for cryptographic correctness that is not what this module asserts (it asserts agility, not ML-DSA conformance). Deferred to the activation procedure. |

## Consequences

- Adding an algorithm is a new `SignatureProvider` plus one registry entry; `DocumentSigner` and
  every other call site are untouched. This is verified, not asserted: `DocumentSignerTest` drives
  the identical call site across all algorithms.
- The post-quantum migration is reduced to swapping the placeholder primitive for a real one:
  replace the JCA names in `postQuantumPlaceholder()` with JDK 24's
  `Signature.getInstance("ML-DSA")` or a BouncyCastle PQC provider, register it, and ship. No
  registry, interface, handle, or call-site change. The activation procedure below is the whole
  migration.
- Because the placeholder is **not** real ML-DSA, this module must never be read as ML-DSA
  conformance or quantum resistance. The placeholder is loud in `JcaSignatureProviders` and here so the
  boundary is unmistakable.
- A verifier never crashes on untrusted input: a malformed or relabeled public key, payload, or
  signature is a verification failure (`false`), and only a genuinely missing JCA algorithm — a
  provider-internal, non-attacker-controlled name — throws.

### Activation procedure — placeholder to real ML-DSA

```text
1. Add a real provider:  Signature.getInstance("ML-DSA")  (JDK 24)  or  BouncyCastlePQCProvider.
2. Replace JcaSignatureProviders.postQuantumPlaceholder() so its JcaSignatureProvider names the real
   key-pair generator, signature, and key-factory algorithms. SignatureAlgorithm.ML_DSA_44 is
   unchanged (it already carries the ML-DSA-44 wire identifier).
3. Register it. DocumentSigner and all call sites are untouched — that is the property under test.
```
