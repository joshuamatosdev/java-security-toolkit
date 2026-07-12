# Supply Chain

Build-evidence and policy utilities for CycloneDX SBOM parsing, immutable action pins, container
base-image pins, wrapper checks, and trust-anchor verification. Parsers return small immutable
projections; policy checks fail closed on malformed or unclassified input.

The module's own tests consume its generated SBOM as executable build evidence.

Verify with `./gradlew :supply-chain:test`.
