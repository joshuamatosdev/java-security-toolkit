# Conventions

This repo is modular and portable: each module is independently buildable and
liftable.

- **One module = one pattern.** Each lives in its own directory with its own
  `build.gradle.kts`, `README.md`, an ADR in `docs/adr/`, and tests.
- **Buildable from a clean clone.** `./gradlew :<module>:test` must pass with
  only JDK 21 + Docker installed. No hidden local state.
- **Package namespace:** `io.github.joshuamatosdev.security.<module>`.
- **Versions** are pinned centrally in `gradle/libs.versions.toml`.
- **ADRs** are append-only decision records; one per featured pattern, plus the
  cross-cutting posture record (ADR-0001).
- **Sanitization:** no real production identifiers, tenant IDs, realm names,
  endpoints, or secrets. Neutral fictional examples only (`acme`, `globex`).
- **Commits:** plain messages, no co-author trailers.
