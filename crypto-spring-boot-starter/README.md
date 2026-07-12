# Crypto Spring Boot Starter

Auto-configures the [`crypto`](../crypto/) provider registry, envelope codec, audit sink, and
verification service. A `DefaultDocumentSigner` is created only when key resolution is available;
the verification-only `DocumentSigner` remains usable without signing capability.

Applications add `SignatureProvider` beans for custom algorithms and may replace any default bean.

Verify with `./gradlew :crypto-spring-boot-starter:test`.
