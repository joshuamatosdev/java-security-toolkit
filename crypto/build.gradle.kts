plugins {
    `java-library`
}

dependencies {
    api(project(":shared"))

    testImplementation(project(":crypto-testkit"))
}
