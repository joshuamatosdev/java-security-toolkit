# Authorization Showcase

A runnable Spring MVC document API demonstrating the framework-free
[`authorization`](../authorization/) core. It composes route authorization, resource-aware policy,
auditing, persistence, and PostgreSQL-backed integration tests.

This is a demonstration application, not a published library. Production adopters should depend
on the core and optional starter, then provide their own policy repository and web boundary.

Verify with `./gradlew :authorization-showcase:test`.
