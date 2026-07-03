# Shared

The identity kernel for the toolkit.

`shared` owns small typed identifiers. More than one module uses them.
Without it, each module copies them. Those copies would be incompatible.

## Included Types

- `TenantId`
- `OrganizationId`
- `TeamId`
- `ResourceId`
- `RequiredText` — the required-text rule set. Text must not be blank. No
  whitespace at the edges. No control characters allowed. Used at
  configuration and construction boundaries.

Each identifier wraps a UUID. Each has a narrow factory API. They share one
contract. It parses canonical-form UUIDs. It rejects the nil UUID. Null input
throws `NullPointerException`. Some modules expose these types publicly. Those
modules depend with `api` scope. `tenant-isolation` and `authorization` do
this. The types stay compile-visible to consumers:

```kotlin
api(project(":shared"))
```

Some consumers build compatible identifier types. They can reuse
`shared-testkit` contract tests:

```kotlin
testImplementation(project(":shared-testkit"))
```

## Run It

`shared` has no standalone runtime. The build compiles and tests it:

```bash
../gradlew :shared:build
../gradlew :shared-testkit:test
../gradlew build
```

## Rules

- Many modules may use a type. Put it here once.
- Module-specific types stay in their module.
- Keep shared types small and immutable. Keep their dependencies light.
