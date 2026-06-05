plugins {
    `java-library`
    alias(libs.plugins.cyclonedx.bom)
}

java {
    toolchain { languageVersion = JavaLanguageVersion.of(21) }
}

dependencies {
    api(project(":crypto-agility-core"))
    api("org.junit.jupiter:junit-jupiter-api:5.11.4")
    api("org.junit.jupiter:junit-jupiter-params:5.11.4")
    api("org.assertj:assertj-core:3.26.3")

    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.11.4")
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
