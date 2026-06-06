plugins {
    `java-library`
    alias(libs.plugins.cyclonedx.bom)
    alias(libs.plugins.owasp.dependencycheck)
}

java {
    toolchain { languageVersion = JavaLanguageVersion.of(21) }
}

dependencies {
    api(libs.jspecify)
    implementation(libs.jackson.databind)

    testImplementation(project(":supply-chain-testkit"))
    testImplementation(platform("org.junit:junit-bom:5.11.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation(libs.assertj.core)
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

dependencyCheck {
    failBuildOnCVSS = 7.0f
    formats = listOf("HTML", "JSON")
}

tasks.test {
    useJUnitPlatform()
    dependsOn(cyclonedxDirectBom)
    systemProperty(
        "sbom.path",
        layout.buildDirectory.file("reports/bom.json").get().asFile.absolutePath,
    )
    systemProperty(
        "dockerfile.path",
        layout.projectDirectory.file("Dockerfile").asFile.absolutePath,
    )
}
