# Conventions

This repo is modular and portable. Each module builds on its own. Each module lifts out cleanly.

- **One module = one pattern.** Each has its own directory. It holds `build.gradle.kts` and `README.md`. Plus an ADR in `docs/adr/`. Plus tests.
- **Buildable from a clean clone.** `./gradlew :<module>:test` must pass. Only JDK 21 and Docker installed. No hidden local state.
- **Package namespace:** `io.github.joshuamatosdev.security.<module>`.
- **Folder size:** no source folder reaches six files. Split into cohesive sub-packages. Keep each at five files max. Name shared sub-packages the same everywhere. Examples: `config`, `web`, `persistence`.
- **Shared types: no class repeats.** Does a type span two modules? It lives once in `shared`. That is the identity kernel. It holds `TenantId`, `OrganizationId`, `ResourceId`. Modules depend via `implementation(project(":shared"))`. No class is ever duplicated.
- **Versions** pin centrally in `gradle/libs.versions.toml`.
- **ADRs** are append-only decision records. One per featured pattern. Plus the cross-cutting posture record (ADR-0001).
- **Sanitization:** no real values allowed. No production identifiers or tenant IDs. No realm names or endpoints. No secrets. Neutral fictional examples only. Like `acme` and `globex`.
- **Commits:** plain messages. No co-author trailers.
