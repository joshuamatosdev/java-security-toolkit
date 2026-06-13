plugins {
    `java-library`
    alias(libs.plugins.cyclonedx.bom)
}

dependencies {
    api(project(":crypto-agility"))
    api(libs.junit.jupiter.params)
}
