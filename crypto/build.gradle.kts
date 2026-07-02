plugins {
    `java-library`
    alias(libs.plugins.cyclonedx.bom)
}

dependencies {
    testImplementation(project(":crypto-testkit"))
}
