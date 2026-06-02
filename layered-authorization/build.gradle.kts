plugins {
    java
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dep.management)
}

java {
    toolchain { languageVersion = JavaLanguageVersion.of(21) }
}

dependencies {
    implementation(project(":shared"))
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation(libs.jspecify)

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
}

tasks.test {
    useJUnitPlatform()
    // No Testcontainers / no database in this module — the authorization decision is a pure,
    // in-memory function and the request gate is a slice test. So the Docker Engine api.version
    // pin that the tenant-isolation module needs does not apply here.
}
