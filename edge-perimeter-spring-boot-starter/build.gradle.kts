plugins {
    `java-library`
    alias(libs.plugins.spring.dep.management)
}

java {
    toolchain { languageVersion = JavaLanguageVersion.of(21) }
}

extra["netty.version"] = libs.versions.netty.get()

dependencyManagement {
    imports {
        mavenBom("org.springframework.boot:spring-boot-dependencies:${libs.versions.springBoot.get()}")
    }
}

dependencies {
    api(project(":edge-perimeter"))
    implementation("org.springframework.boot:spring-boot")
    implementation("org.springframework.boot:spring-boot-autoconfigure")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
}
