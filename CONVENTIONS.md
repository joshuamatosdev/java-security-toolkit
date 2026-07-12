# Conventions

This repo is modular and portable. Each module builds on its own. Each module lifts out cleanly.

- **One module = one cohesive capability.** Each module has its own directory, `build.gradle.kts`, `README.md`, and focused tests.
- **Buildable from a clean clone.** `./gradlew :<module>:test` must pass. Only JDK 21 and Docker installed. No hidden local state.
- **Package namespace:** `io.github.joshuamatosdev.security.<module>`.
- **Package cohesion:** split packages when types have different reasons to change or distinct dependency directions. Do not split only to satisfy a file-count threshold. Name equivalent concerns consistently, such as `config`, `web`, and `persistence`.
- **Shared types: no class repeats.** Does a type span two modules? It lives once in `shared`. That is the identity kernel. It holds `TenantId`, `OrganizationId`, `ResourceId`. Modules depend via `implementation(project(":shared"))`. No class is ever duplicated.
- **Versions** pin centrally in `gradle/libs.versions.toml`.
- **Replaceable mechanisms:** algorithms and provider-specific behavior sit behind typed interfaces or registries. Shipped implementations are defaults, not hard-coded closed sets.
- **Sanitization:** no real values allowed. No production identifiers or tenant IDs. No realm names or endpoints. No secrets. Neutral fictional examples only. Like `acme` and `globex`.
- **Git workflow:** commit and push directly to `main`. Do not create other branches or pull requests.
- **Commits:** plain messages.
