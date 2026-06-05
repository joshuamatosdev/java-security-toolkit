plugins {
    `java-library`
    alias(libs.plugins.spring.dep.management)
}

java {
    toolchain { languageVersion = JavaLanguageVersion.of(21) }
}

dependencyManagement {
    imports {
        mavenBom("org.springframework.boot:spring-boot-dependencies:${libs.versions.springBoot.get()}")
    }
}

dependencies {
    api(project(":edge-perimeter"))
    api("org.junit.jupiter:junit-jupiter-api:5.11.4")
    api("org.assertj:assertj-core:3.26.3")

    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.11.4")
}

tasks.test {
    useJUnitPlatform()
}
