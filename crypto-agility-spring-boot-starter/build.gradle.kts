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

val cyclonedxDirectBom = tasks.named<org.cyclonedx.gradle.CyclonedxDirectTask>("cyclonedxDirectBom") {
    includeConfigs = listOf("runtimeClasspath")
    jsonOutput.set(file("build/reports/bom.json"))
    xmlOutput.unsetConvention()
    schemaVersion = org.cyclonedx.Version.VERSION_15
    projectType = org.cyclonedx.model.Component.Type.LIBRARY
}
// Realize during configuration so the plugin's outgoing artifact variant exists before other projects consume this module.
cyclonedxDirectBom.get()

tasks.test {
    useJUnitPlatform()
}

tasks.named("check") {
    dependsOn(cyclonedxDirectBom)
}
