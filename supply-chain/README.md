# Supply Chain Compatibility Artifact

This module is retained as a compatibility aggregate for existing consumers.
The runnable implementation now lives in `supply-chain-core`, and reusable
contract tests live in `supply-chain-testkit`.

`supply-chain-core` is a runnable reference for hardening the build's trust
horizon: pin the build tool, verify dependencies, enumerate what ships, scan
for known vulnerabilities, and pin the runtime base image. Every dependency,
the build tool, and the base image is code that executes, so the module treats
them as such.

It covers the cross-cutting supply-chain layer of the
[five-layer posture](../docs/adr/0001-five-layer-security-posture.md). The decision record is
[ADR-0005](../docs/adr/0005-supply-chain-trust-horizon.md).

## Table of Contents

- [Quick Start](#quick-start)
- [What It Demonstrates](#what-it-demonstrates)
- [SBOM Integrity Gate](#sbom-integrity-gate)
- [Base-Image-Pin Policy](#base-image-pin-policy)
- [Dependency Scan](#dependency-scan)
- [Activation Procedures](#activation-procedures)
- [Testing](#testing)

## Quick Start

Requirements:

- JDK 21 (no Docker, no network for the default build — dependencies resolve once, then the SBOM
  and the tests run offline)

```bash
../gradlew :supply-chain-core:test
```

## What It Demonstrates

| Control | Where |
|---|---|
| Build-tool pin | `gradle/wrapper/gradle-wrapper.properties` carries `distributionSha256Sum` |
| CycloneDX SBOM on build | `build.gradle.kts` applies `org.cyclonedx.bom`; `cyclonedxBom` emits `build/reports/bom.json` |
| SBOM integrity gate | `supply-chain-core` `SbomReader` + `SbomIntegrityTest` assert on the real generated bill |
| Dependency scan | `org.owasp.dependencycheck`, `failBuildOnCVSS = 7.0`, CI/on-demand |
| Base-image-pin policy | `Dockerfile` digest-pinned; `BaseImagePolicy` + `BaseImagePolicyTest` enforce it |
| Dependency verification | repo-global trust anchor — activation documented below |

## SBOM Integrity Gate

`cyclonedxBom` emits a CycloneDX 1.5 bill on every build. The `test` task `dependsOn("cyclonedxBom")`
and passes `-Dsbom.path`, so `SbomIntegrityTest` checks the **real** generated
`build/reports/bom.json` — not a fixture. It asserts the document is CycloneDX, carries a unique
`serialNumber`, enumerates the resolved components, and that every component has a `purl` coordinate
(so each can be cross-checked against an advisory feed).

## Base-Image-Pin Policy

The runtime `Dockerfile` pins every external `FROM` by `@sha256` digest. A tag like `21-jre` is
mutable — the registry can repoint it — so a tag-based build is not reproducible or tamper-evident.
`BaseImagePolicy` parses the `supply-chain-core` Dockerfile (excluding internal
multi-stage references and `scratch`) and `BaseImagePolicyTest` fails the build
if any external image uses a floating tag. Refresh a digest with:

```bash
docker buildx imagetools inspect eclipse-temurin:21-jre --format '{{.Manifest.Digest}}'
```

## Dependency Scan

OWASP dependency-check is applied and configured to fail on any High-or-worse finding
(`failBuildOnCVSS = 7.0`). It is **not** wired into `check` — the NVD feed needs network and an
`NVD_API_KEY`, which would break the offline build contract. Run it on demand / in CI:

```bash
NVD_API_KEY=... ../gradlew :supply-chain-core:dependencyCheckAnalyze
```

## Activation Procedures

Two controls are repo-global trust anchors a consuming repository turns on once (see
[ADR-0005](../docs/adr/0005-supply-chain-trust-horizon.md) for why they are documented rather than
committed into this multi-module showcase):

```bash
# Dependency verification — record a SHA-256 for every resolved artifact, then prove enforcement
# by flipping one byte and confirming the build fails with "Dependency verification failed".
../gradlew --write-verification-metadata sha256 build

# Reproducible resolution — lock every configuration.
#   dependencyLocking { lockAllConfigurations() }   // in build.gradle.kts
../gradlew dependencies --write-locks
```

## Testing

```bash
../gradlew :supply-chain-core:test --tests "*SbomIntegrityTest"
../gradlew :supply-chain-core:test --tests "*BaseImagePolicyTest"
../gradlew :supply-chain-testkit:test
```

Every claim is proven by an observable artifact — the generated SBOM and the Dockerfile — not by
reading the build configuration.
