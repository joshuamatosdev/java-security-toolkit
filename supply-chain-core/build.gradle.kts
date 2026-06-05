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
    testImplementation("org.assertj:assertj-core:3.26.3")
}

tasks.named<org.cyclonedx.gradle.CycloneDxTask>("cyclonedxBom") {
    setIncludeConfigs(listOf("runtimeClasspath"))
    setOutputFormat("json")
    setSchemaVersion("1.5")
    setProjectType("library")
    setOutputName("bom")
}

dependencyCheck {
    failBuildOnCVSS = 7.0f
    formats = listOf("HTML", "JSON")
}

tasks.test {
    useJUnitPlatform()
    dependsOn("cyclonedxBom")
    systemProperty(
        "sbom.path",
        layout.buildDirectory.file("reports/bom.json").get().asFile.absolutePath,
    )
    systemProperty(
        "dockerfile.path",
        layout.projectDirectory.file("Dockerfile").asFile.absolutePath,
    )
}
