plugins {
    `java-library`
    id("org.cyclonedx.bom")
}

dependencies {
    api(project(":crypto"))
}
