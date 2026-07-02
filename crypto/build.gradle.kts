plugins {
    `java-library`
    alias(libs.plugins.cyclonedx.bom)
}

dependencies {
    api(project(":shared"))

    testImplementation(project(":crypto-testkit"))
}
