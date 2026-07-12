# Edge Spring Boot Starter

Auto-configures the [`edge`](../edge/) WebFlux perimeter. Credential-plane-independent controls
always load in reactive applications; browser and service security chains activate only when their
OAuth2 infrastructure is present.

The immutable `BrowserRouteTable` is replaceable as a bean, keeping route matching and
authorization strategies plug-in friendly.

Verify with `./gradlew :edge-spring-boot-starter:test`.
