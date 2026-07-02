# Shared

The cross-module identity kernel for the security architecture modules.

`shared` owns small typed identifiers that are used by more than one module.
Keeping them here prevents each module from creating its own incompatible copy
of the same concept.

## Included Types

- `TenantId`
- `OrganizationId`
- `TeamId`
- `ResourceId`
- `RequiredText` — the single required-text rule set (non-blank, no edge
  whitespace, no control characters) for configuration and construction
  boundaries.

Each identifier wraps a UUID and provides a narrow factory API with one shared
contract: canonical-form parsing, nil-UUID rejection, and
`NullPointerException` on null. Modules that expose these types in their own
public signatures depend on them with `api` scope (as `tenant-isolation` and
`authorization` do), so the types stay compile-visible to consumers:

```kotlin
api(project(":shared"))
```

Consumers that implement compatible identifier types can reuse
`shared-testkit` contract tests:

```kotlin
testImplementation(project(":shared-testkit"))
```

## Run It

`shared` has no standalone runtime. It is compiled and tested as part of the
repository build:

```bash
../gradlew :shared:build
../gradlew :shared-testkit:test
../gradlew build
```

## Rules

- A type used by more than one module belongs here once.
- Module-specific types stay in their owning module.
- Shared types should remain small, immutable, and dependency-light.
