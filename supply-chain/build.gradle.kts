plugins {
    `java-library`
    id("org.owasp.dependencycheck")
}

dependencies {
    api(libs.jspecify)
    implementation(libs.jackson.databind)

    testImplementation(project(":supply-chain-testkit"))
}

dependencyCheck {
    failBuildOnCVSS = 7.0f
    formats = listOf("HTML", "JSON")
}

tasks.test {
    dependsOn(tasks.named("cyclonedxDirectBom"))
    systemProperty(
        "sbom.path",
        layout.buildDirectory.file("reports/bom.cdx.json").get().asFile.absolutePath,
    )
    systemProperty(
        "dockerfile.path",
        layout.projectDirectory.file("Dockerfile").asFile.absolutePath,
    )
    systemProperty(
        "wrapper.properties.path",
        rootProject.file("gradle/wrapper/gradle-wrapper.properties").absolutePath,
    )
    systemProperty(
        "workflows.dir",
        rootProject.file(".github/workflows").absolutePath,
    )
}
