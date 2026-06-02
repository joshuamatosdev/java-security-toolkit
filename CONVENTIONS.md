# Conventions

This repo is modular and portable: each module is independently buildable and
liftable.

- **One module = one pattern.** Each lives in its own directory with its own
  `build.gradle.kts`, `README.md`, an ADR in `docs/adr/`, and tests.
- **Buildable from a clean clone.** `./gradlew :<module>:test` must pass with
  only JDK 21 + Docker installed. No hidden local state.
- **Package namespace:** `io.github.joshuamatosdev.security.<module>`.
- **Folder size:** no source folder holds 6 or more files. Split into cohesive
  sub-packages (≤5 files each), and name the sub-packages consistently across
  modules where the concept is shared (`config`, `web`, `persistence`, …).
- **Shared types — no class repeats.** A type used by more than one module lives
  exactly once in the `shared` module (the identity kernel: `TenantId`,
  `OrganizationId`, `ResourceId`). Modules depend on it via
  `implementation(project(":shared"))`; a class is never duplicated across modules.
- **Versions** are pinned centrally in `gradle/libs.versions.toml`.
- **ADRs** are append-only decision records; one per featured pattern, plus the
  cross-cutting posture record (ADR-0001).
- **Sanitization:** no real production identifiers, tenant IDs, realm names,
  endpoints, or secrets. Neutral fictional examples only (`acme`, `globex`).
- **Commits:** plain messages, no co-author trailers.
