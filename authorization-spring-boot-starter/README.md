# Authorization Spring Boot Starter

Auto-configures the [`authorization`](../authorization/) policy, rule repository, audit sink, and
authorization service. Servlet applications also receive the generic HTTP 403 translation for
known authorization denials; non-web applications keep a web-free runtime.

Applications can replace each default bean independently.

The default rule repository grants no role-based permissions. Applications should provide a
production `PolicyRuleRepository`. The seeded in-memory showcase policy is available only through
the explicit local-demo switch:

```yaml
authorization:
  demo-policy:
    enabled: true
```

Do not enable the demo policy in deployments.

Verify with `./gradlew :authorization-spring-boot-starter:test`.
