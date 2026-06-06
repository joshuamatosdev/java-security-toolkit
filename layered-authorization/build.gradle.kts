plugins {
    `java-library`
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dep.management)
}

java {
    toolchain { languageVersion = JavaLanguageVersion.of(21) }
}

extra["tomcat.version"] = libs.versions.tomcat.get()
extra["commons-lang3.version"] = libs.versions.commonsLang3.get()

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

dependencyManagement {
    imports {
        mavenBom("org.testcontainers:testcontainers-bom:${libs.versions.testcontainers.get()}")
    }
}

tasks.test {
    useJUnitPlatform()
    // Match tenant-isolation: PG18 Testcontainers owns database identifier behavior, including uuidv7().
    systemProperty("api.version", "1.44")
}
