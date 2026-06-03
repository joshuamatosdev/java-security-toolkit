# Shared

The cross-module identity kernel for the security architecture modules.

`shared` owns small typed identifiers that are used by more than one module.
Keeping them here prevents each module from creating its own incompatible copy
of the same concept.

## Included Types

- `TenantId`
- `OrganizationId`
- `ResourceId`

Each type wraps a UUID and provides a narrow factory API. Modules depend on
these identifiers through:

```kotlin
implementation(project(":shared"))
```

## Run It

`shared` has no standalone runtime. It is compiled and tested as part of the
repository build:

```bash
../gradlew :shared:build
../gradlew build
```

## Rules

- A type used by more than one module belongs here once.
- Module-specific types stay in their owning module.
- Shared types should remain small, immutable, and dependency-light.
