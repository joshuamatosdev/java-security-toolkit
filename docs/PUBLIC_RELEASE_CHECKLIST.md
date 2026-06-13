# Public Release Checklist

Use this checklist before publishing Bulwark to a public host or
cutting a public release tag.

## Repository Scrub

- Confirm the repository contains only fictional tenants, organizations, users,
  documents, endpoints, and credentials.
- Confirm `.env`, local IDE state, generated build output, and machine-local
  tool state are ignored and absent from tracked files.
- Review the full Git history before making the repository public, not just the
  current tree.
- If a real secret was ever committed, rotate it before publication even if it
  has since been removed.

Suggested current-tree scan:

```bash
rg -n -i "(api[_-]?key|client[_-]?secret|private[_-]?key|password|passwd|token|bearer|credential|secret)" .
```

Suggested history scan:

```bash
git log -p --all -G"(api[_-]?key|client[_-]?secret|private[_-]?key|password|passwd|token|bearer|credential|secret)"
```

Optional dedicated scanners:

```bash
gitleaks detect --source . --redact --verbose
trufflehog git file://$PWD
```

Review all findings manually. This repository intentionally contains words such
as `secret`, `credential`, and `password` in test names, configuration validation,
and security documentation, so keyword hits are not automatically leaks.

## Build And Test

```bash
./gradlew test
./gradlew build publishToMavenLocal
./gradlew :supply-chain:cyclonedxDirectBom :crypto-agility:cyclonedxDirectBom :crypto-agility-spring-boot-starter:cyclonedxDirectBom :crypto-agility-testkit:cyclonedxDirectBom
NVD_API_KEY=... ./gradlew dependencyCheckPurge dependencyCheckAggregate
git diff --check
```

For starter and testkit changes, include focused verification for the affected
artifacts before the full build:

```bash
./gradlew :tenant-isolation-spring-boot-starter:test :tenant-isolation-testkit:test
./gradlew :layered-authorization-spring-boot-starter:test :layered-authorization-testkit:test
./gradlew :edge-perimeter-spring-boot-starter:test :edge-perimeter-testkit:test
./gradlew :shared-testkit:test :supply-chain-testkit:test
```

For a clean-clone check, clone the repository into a temporary directory and run
`./gradlew build` with only JDK 21 and Docker available.

## Public Framing

- README states that this is production-oriented OSS for adoption into real
  applications, with explicit environment-specific responsibilities.
- README explains the module map, adoption paths, and what each test suite
  proves.
- Crypto-agility docs show install, plain Java setup, Spring Boot setup,
  provider extension, key custody, rotation, and compliance boundaries.
- Cryptography wording distinguishes algorithm identity from validated runtime
  compliance.
- Public docs do not claim managed-service support, certification, or compliance
  status unless those are backed by a separate release or agreement.

## GitHub Setup

- Enable GitHub secret scanning for the public repository.
- Enable branch protection for `main`.
- Require the `ci` workflow before merge.
- Enable Dependabot alerts and security updates.
- Enable private vulnerability reporting if the host supports it.

## Release

- Tag releases from `main`.
- Update [CHANGELOG.md](../CHANGELOG.md).
- Confirm [LICENSE](../LICENSE) and [NOTICE](../NOTICE) are present.
- Publish release notes that describe the project as production-oriented OSS and
  call out adoption contracts, replacement points, and known limitations.
