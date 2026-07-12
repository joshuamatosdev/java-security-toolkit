plugins {
    `kotlin-dsl`
}

repositories {
    gradlePluginPortal()
    mavenCentral()
}

dependencies {
    implementation(
        "io.spring.dependency-management:io.spring.dependency-management.gradle.plugin:${libs.versions.springDepMgmt.get()}"
    )
    implementation(
        "org.cyclonedx.bom:org.cyclonedx.bom.gradle.plugin:${libs.versions.cyclonedx.get()}"
    )
    implementation(
        "org.owasp.dependencycheck:org.owasp.dependencycheck.gradle.plugin:${libs.versions.dependencyCheck.get()}"
    )
}
