plugins {
    `java-library`
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dep.management)
}

dependencies {
    api("org.springframework.boot:spring-boot-starter-webflux")
    api("org.springframework.boot:spring-boot-starter-oauth2-client")
    api("org.springframework.boot:spring-boot-starter-oauth2-resource-server")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")

    // The module runs its own shipped contracts, so a testkit regression cannot ship silently.
    testImplementation(project(":edge-testkit"))
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.boot:spring-boot-starter-webflux-test")
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("io.projectreactor:reactor-test")
    // In-process JWKS endpoint so the REAL resource-server decoder can fetch keys and verify a
    // signed bearer token end-to-end (mockJwt() bypasses the decoder, so it cannot prove the
    // issuer/audience boundary actually runs). In-process only — no Docker, preserving the
    // JDK-21-only build contract. Pinned centrally in libs.versions.toml (okhttp 4.12.0, the
    // version Spring Boot 3.5.x manages for okhttp3).
    testImplementation(libs.mockwebserver)
}
