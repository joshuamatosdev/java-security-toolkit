plugins {
    `java-library`
    alias(libs.plugins.spring.dep.management)
    alias(libs.plugins.cyclonedx.bom)
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
    api(project(":crypto-agility-core"))

    implementation("org.springframework.boot:spring-boot")
    implementation("org.springframework.boot:spring-boot-autoconfigure")
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.named<org.cyclonedx.gradle.CycloneDxTask>("cyclonedxBom") {
    setIncludeConfigs(listOf("runtimeClasspath"))
    setOutputFormat("json")
    setSchemaVersion("1.5")
    setProjectType("library")
    setOutputName("bom")
}

tasks.test {
    useJUnitPlatform()
}

tasks.named("check") {
    dependsOn("cyclonedxBom")
}
