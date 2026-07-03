plugins {
    `java-library`
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dep.management)
}

dependencies {
    api(project(":shared"))
    api("org.springframework.boot:spring-boot-starter-data-jpa")
    api(libs.jspecify)
    runtimeOnly(libs.postgresql)
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("com.tngtech.archunit:archunit-junit5:1.4.2")
    testImplementation("org.testcontainers:testcontainers-junit-jupiter")
    testImplementation("org.testcontainers:testcontainers-postgresql")
    testRuntimeOnly(libs.commons.compress)
    testRuntimeOnly(libs.commons.lang3)
}

tasks.test {
    // Pin the Docker Engine API version negotiated by Testcontainers' docker-java client to one
    // served by Docker Engine 25–29+. Very new local daemons (Docker Desktop 29.x) otherwise
    // reject the auto-negotiated version with HTTP 400 on /info. Harmless on CI's older daemons.
    systemProperty("api.version", "1.44")
}
