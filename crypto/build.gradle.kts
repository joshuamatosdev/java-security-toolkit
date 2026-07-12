plugins {
    `java-library`
    id("org.cyclonedx.bom")
}

dependencies {
    api(project(":shared"))

    testImplementation(project(":crypto-testkit"))
}
