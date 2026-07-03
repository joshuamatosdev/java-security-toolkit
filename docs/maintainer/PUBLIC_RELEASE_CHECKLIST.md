# Public Release Checklist

Use this checklist first. Before publishing to a public host. Before cutting a public release tag.

## Repository Scrub

- Confirm only fictional data remains. Tenants. Organizations. Users. Documents. Endpoints. Credentials.
- Confirm these are ignored and untracked. `.env`. Local IDE state. Generated build output. Machine-local tool state.
- Review the full Git history first. Not just the current tree.
- Was a real secret ever committed? Rotate it before publication. Do this even if removed.

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

Review all findings manually. This repository includes such words deliberately. Like `secret`, `credential`, `password`. They appear in test names. Also in configuration validation. Also in security documentation. Keyword hits are not automatic leaks.

## Build And Test

```bash
./gradlew test
./gradlew build publishToMavenLocal
./gradlew :supply-chain:cyclonedxDirectBom :crypto:cyclonedxDirectBom :crypto-spring-boot-starter:cyclonedxDirectBom :crypto-testkit:cyclonedxDirectBom
NVD_API_KEY=... ./gradlew dependencyCheckPurge dependencyCheckAggregate
git diff --check
```

Changing a starter or testkit? Verify the affected artifacts first. Do this before the full build:

```bash
./gradlew :tenant-isolation-spring-boot-starter:test :tenant-isolation-testkit:test
./gradlew :authorization-spring-boot-starter:test :authorization-testkit:test
./gradlew :edge-spring-boot-starter:test :edge-testkit:test
./gradlew :shared-testkit:test :supply-chain-testkit:test
```

For a clean-clone check, do this. Clone into a temporary directory. Run `./gradlew build` there. Allow only JDK 21 and Docker.

## Public Framing

- README calls this production-oriented OSS. It is meant for real applications. It names environment-specific responsibilities clearly.
- README explains three things. The module map. The adoption paths. What each test suite proves.
- Crypto docs cover the whole path. Install. Plain Java setup. Spring Boot setup. Provider extension. Key custody. Rotation. Compliance boundaries.
- Crypto wording separates two ideas. Algorithm identity. Validated runtime compliance.
- Public docs claim no managed-service support. They claim no certification. They claim no compliance status. Exception: a separate release or agreement.

## GitHub Setup

- Enable GitHub secret scanning.
- Enable branch protection for `main`.
- Require the `ci` workflow before merge.
- Enable Dependabot alerts and security updates.
- Enable private vulnerability reporting if supported.

## Release

- Tag releases from `main`.
- Update [CHANGELOG.md](../../CHANGELOG.md).
- Confirm [LICENSE](../../LICENSE) and [NOTICE](../../NOTICE) are present.
- Publish release notes. Describe the project as production-oriented OSS. Call out the adoption contracts. Call out the replacement points. Call out known limitations.
