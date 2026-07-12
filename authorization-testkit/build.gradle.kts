plugins {
    `java-library`
    id("io.spring.dependency-management")
}

dependencies {
    api(project(":authorization"))
}
