plugins {
    `java-library`
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dep.management)
}

dependencies {
    api(project(":shared"))
    api("org.springframework.boot:spring-boot-starter-web")
    api("org.springframework.boot:spring-boot-starter-security")
    api("org.springframework.boot:spring-boot-starter-data-jpa")
    api(libs.jspecify)
    runtimeOnly(libs.postgresql)

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("org.testcontainers:junit-jupiter")
    testImplementation("org.testcontainers:postgresql")
    testRuntimeOnly(libs.commons.compress)
    testRuntimeOnly(libs.commons.lang3)
}

tasks.test {
    // Match tenant-isolation: PG18 Testcontainers owns database identifier behavior, including uuidv7().
    systemProperty("api.version", "1.44")
}
