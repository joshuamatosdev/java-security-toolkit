plugins {
    `java-library`
}

dependencies {
    api(libs.jspecify)

    testImplementation(project(":shared-testkit"))
}
