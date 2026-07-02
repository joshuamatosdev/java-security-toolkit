plugins {
    java
    id("org.springframework.boot")
    id("io.spring.dependency-management")
}

java {
    toolchain { languageVersion = JavaLanguageVersion.of(21) }
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")
    implementation("org.springframework.boot:spring-boot-starter-jdbc")
    // Layer 5: tenant placement, signed session claims, PostgreSQL RLS.
    implementation("io.github.joshuamatosdev.security:tenant-isolation-spring-boot-starter:0.1.0-SNAPSHOT")
    // Layer 2: the framework-free decision core, wired by its starter.
    implementation("io.github.joshuamatosdev.security:authorization-spring-boot-starter:0.1.0-SNAPSHOT")
    runtimeOnly("org.postgresql:postgresql")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("org.testcontainers:postgresql")
}

tasks.withType<Test> {
    useJUnitPlatform()
}
