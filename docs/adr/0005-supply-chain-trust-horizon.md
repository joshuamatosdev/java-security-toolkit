# ADR-0005: Supply-Chain Trust Horizon — Pin, Verify, and Enumerate Every Build Input

- **Status:** Accepted
- **Date:** 2026-06-03

## Context

The build is a trust horizon. Every dependency, the build tool itself, and the runtime base
image are code that executes — at compile time, at `bootRun`, on the CI runner, and in production.
A control at the application layer (Layers 1–5 of [ADR-0001](0001-five-layer-security-posture.md))
is moot if the artifact it ships inside was assembled from inputs no one verified.

The failure modes are quiet and common enough to justify executable checks:

- **Dependency trust on TLS alone.** Without Gradle dependency-verification metadata, the build
  accepts whatever JAR a configured repository serves. A compromised mirror, a typo-squat upload,
  or a poisoned `~/.m2` artifact lands code execution at build time. A seed file such as
  `verification-metadata.dryrun.xml` is not protection until it is promoted to the active metadata
  file Gradle enforces.
- **Unpinned build tool.** A `gradle-wrapper.properties` without `distributionSha256Sum` trusts
  the wrapper download host; `validateDistributionUrl` checks the URL, not the bytes.
- **Non-reproducible resolution.** Without a lockfile, two builds at different times can resolve
  different transitives through BOM aliases, so a CVE remediation cannot be reasoned about over time.
- **No bill of materials.** Without an SBOM, "what is actually in this artifact, and is any of it
  vulnerable" has no machine-checkable answer.
- **Floating base-image tags.** A `FROM image:tag` is mutable — the registry can repoint the tag at
  new content between builds, so the runtime layer is neither reproducible nor tamper-evident.

## Decision

Pin, verify, and enumerate every build input. Each control is a distinct layer of the same horizon.

### Pin the build tool

`gradle-wrapper.properties` carries `distributionSha256Sum`, pinning the exact Gradle distribution
by content hash (fetched from the distribution host, not transcribed from a build log).
`WrapperPinPolicy` + `WrapperPinPolicyTest` assert on the **real** repository wrapper properties —
that the distribution is pinned by a lowercase 64-hex SHA-256, fetched over HTTPS, with
`validateDistributionUrl` enabled — so the pin is an executable check, not a value that can silently
regress (for example, a `gradle wrapper` regeneration that drops the checksum).

The committed `gradle-wrapper.jar` is the first code that runs on every `./gradlew` invocation, ahead
of every other control. CI validates that JAR against Gradle's published checksums via
`gradle/actions/setup-gradle` with `validate-wrappers: true`, so a tampered bootstrap JAR fails the
build before it can run.

### Verify dependencies (a repo-global trust anchor)

Gradle dependency verification (`gradle/verification-metadata.xml`) records a SHA-256 for every
resolved artifact and fails the build on any mismatch. It is generated with
`./gradlew --write-verification-metadata sha256 build` and validated by flipping one byte and
confirming the build fails with "Dependency verification failed".

This file is **repo-global**, not per-module: it applies to every configuration of every
subproject. That is documented here as the activation procedure rather than committed into this
multi-module showcase, because forcing checksums across the unrelated modules' dependency closures
(Spring Boot, Testcontainers, …) is an operational decision for the consuming repository, not a
property of the supply-chain pattern itself. The pattern is "verify by content hash"; where the
anchor lives is a repository-topology choice.

### Emit and check an SBOM on every build

The CycloneDX Gradle plugin emits `build/reports/bom.json` on build. An integrity gate
(`SbomReader` + `SbomIntegrityTest`) asserts on the **real generated bill**: it is CycloneDX, it
carries a unique `serialNumber`, it enumerates the resolved components, and every component carries
a `purl` coordinate so it can be cross-checked against an advisory feed.

### Scan dependencies — CI-gated, not offline-default

The OWASP dependency-check plugin is applied **at the build root** and configured with
`failBuildOnCVSS = 7.0` (any High-or-worse finding fails the scan). `dependencyCheckAggregate` scans
every subproject's resolved closure — including the Spring Boot, WebFlux, Netty, Tomcat, and
PostgreSQL runtime dependencies a consumer actually ships, not only this module's direct
dependencies.

It is **not** wired into `check`, because the NVD data feed requires network access and an API key
(`NVD_API_KEY`) — wiring it into the default build would break the offline clean-clone contract every
module holds. Instead the CI workflow runs it as a dedicated job on a weekly schedule and on demand
(`workflow_dispatch`), with the `NVD_API_KEY` secret:
`NVD_API_KEY=... ./gradlew dependencyCheckAggregate`.

### Pin the base image by digest

The runtime `Dockerfile` pins every external `FROM` by `@sha256` digest. `BaseImagePolicy` parses
the Dockerfile — excluding internal multi-stage references and `scratch` — and
`BaseImagePolicyTest` fails the build if any external image is referenced by a mutable tag.

## Rationale

| Alternative | Reason rejected |
|---|---|
| Trust Maven Central / mirrors on TLS | TLS authenticates the host, not the artifact bytes; a compromised mirror or poisoned local cache is accepted silently. |
| A `verification-metadata.dryrun.xml` seed left un-activated | Gradle only enforces the file named `verification-metadata.xml`; a dry-run file is documentation, not a control. |
| Skip the wrapper SHA because `validateDistributionUrl=true` | That validates the URL host, not the downloaded distribution; a host compromise still substitutes a malicious build tool. |
| No SBOM ("we know our dependencies") | Knowledge that is not machine-checkable cannot answer an advisory query across a transitive closure of hundreds of artifacts. |
| Wire the NVD scan into every local build | The NVD feed needs network + an API key; it would break offline builds and couple every commit to an external service's availability. |
| Floating base-image tags ("we always rebuild") | A tag is mutable; the registry can repoint it, so the runtime layer is not reproducible or tamper-evident. A digest names exact bytes. |

## Consequences

- The build tool, the dependency set, and the runtime base layer each have a verifiable identity;
  a substitution at any layer fails a check rather than shipping silently.
- "What is in this artifact" has a machine-checkable answer (the SBOM), regenerated every build and
  asserted for integrity — not a stale document.
- The supply-chain controls couple to build-tool versions: the CycloneDX plugin pinned here tracks
  the showcase's Gradle line, and a toolchain upgrade re-pins the plugin (as the source platform did
  when it moved to a newer Gradle and CycloneDX major).
- Dependency verification and the lockfile are documented activation procedures because they are
  repo-global trust anchors; a consuming repository turns them on once for its whole build.
