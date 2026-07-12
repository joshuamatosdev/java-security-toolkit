# Authorization Spring Boot Starter

Auto-configures the [`authorization`](../authorization/) policy, rule repository, audit sink, and
authorization service. Servlet applications also receive the generic HTTP 403 translation for
known authorization denials; non-web applications keep a web-free runtime.

Applications can replace each default bean independently.

Verify with `./gradlew :authorization-spring-boot-starter:test`.
