plugins {
    `java-library`
    alias(libs.plugins.spring.dep.management)
}

dependencies {
    api(project(":layered-authorization"))
}
