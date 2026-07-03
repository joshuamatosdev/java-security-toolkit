plugins {
    java
    id("org.springframework.boot")
    id("io.spring.dependency-management")
}

java {
    toolchain { languageVersion = JavaLanguageVersion.of(21) }
}

dependencies {
    // Layers 1 and 4: the WebFlux edge perimeter — OIDC + PKCE browser plane, service JWT plane,
    // CORS/CSRF/cookie/header hardening. The starter's api surface brings WebFlux itself.
    implementation("io.github.joshuamatosdev.security:edge-spring-boot-starter:0.1.0-SNAPSHOT")
    implementation("org.springframework.boot:spring-boot-webclient")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.boot:spring-boot-starter-webflux-test")
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("io.projectreactor:reactor-test")
    // In-process downstream double for the relay test. 4.12.0 matches the okhttp3 version the
    // Boot 3.5.x BOM manages for okhttp itself (same pin the edge module uses).
    testImplementation("com.squareup.okhttp3:mockwebserver:5.4.0")
}

tasks.withType<Test> {
    useJUnitPlatform()
}
