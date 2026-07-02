plugins {
    `java-library`
    alias(libs.plugins.cyclonedx.bom)
}

dependencies {
    api(project(":crypto"))
}
