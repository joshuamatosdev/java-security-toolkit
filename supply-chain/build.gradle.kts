plugins {
    java
    alias(libs.plugins.cyclonedx.bom)
    alias(libs.plugins.owasp.dependencycheck)
}

java {
    toolchain { languageVersion = JavaLanguageVersion.of(21) }
}

dependencies {
    implementation(libs.jspecify)
    implementation(libs.jackson.databind)

    testImplementation(platform("org.junit:junit-bom:5.11.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("org.assertj:assertj-core:3.26.3")
}

// CycloneDX SBOM: emit build/reports/bom.json from the runtime classpath on build. Offline once the
// dependency graph is resolved (it reads the resolved graph, not the network).
tasks.named<org.cyclonedx.gradle.CycloneDxTask>("cyclonedxBom") {
    setIncludeConfigs(listOf("runtimeClasspath"))
    setOutputFormat("json")
    setSchemaVersion("1.5")
    setProjectType("library")
    setOutputName("bom")
}

// OWASP dependency scan — the CI / on-demand gate (`./gradlew :supply-chain:dependencyCheckAnalyze`).
// Deliberately NOT wired into `check`: the NVD data feed needs network access and an API key
// (NVD_API_KEY), which would break the offline clean-clone build contract every other module holds.
// failBuildOnCVSS encodes the policy — any High-or-worse finding (CVSS >= 7.0) fails the scan.
dependencyCheck {
    failBuildOnCVSS = 7.0f
    formats = listOf("HTML", "JSON")
}

tasks.test {
    useJUnitPlatform()
    // The integrity test asserts on the REAL generated SBOM, so it must exist before tests run.
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
