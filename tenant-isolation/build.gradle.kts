plugins {
    `java-library`
    jacoco
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dep.management)
}

java {
    toolchain { languageVersion = JavaLanguageVersion.of(21) }
}

dependencies {
    api(project(":shared"))
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation(libs.jspecify)
    runtimeOnly("org.postgresql:postgresql")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("com.tngtech.archunit:archunit-junit5:1.4.2")
    testImplementation("org.testcontainers:junit-jupiter")
    testImplementation("org.testcontainers:postgresql")
}

dependencyManagement {
    imports {
        mavenBom("org.testcontainers:testcontainers-bom:1.20.4")
    }
}

tasks.test {
    useJUnitPlatform()
    // Pin the Docker Engine API version negotiated by Testcontainers' docker-java client to one
    // served by Docker Engine 25–29+. Very new local daemons (Docker Desktop 29.x) otherwise
    // reject the auto-negotiated version with HTTP 400 on /info. Harmless on CI's older daemons.
    systemProperty("api.version", "1.44")
    finalizedBy(tasks.jacocoTestReport)
}

tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports {
        xml.required = true
        html.required = true
        csv.required = false
    }
}
