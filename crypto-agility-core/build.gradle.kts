plugins {
    `java-library`
    alias(libs.plugins.cyclonedx.bom)
}

java {
    toolchain { languageVersion = JavaLanguageVersion.of(21) }
}

dependencies {
    testImplementation(project(":crypto-agility-testkit"))
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

tasks.test {
    useJUnitPlatform()
}

tasks.named("check") {
    dependsOn("cyclonedxBom")
}
