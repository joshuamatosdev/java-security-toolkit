plugins {
    `java-library`
    alias(libs.plugins.spring.dep.management)
    alias(libs.plugins.cyclonedx.bom)
}

dependencies {
    api(project(":crypto-agility"))
    implementation(project(":shared"))

    implementation("org.springframework.boot:spring-boot")
    implementation("org.springframework.boot:spring-boot-autoconfigure")
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
}

// Without the Spring Boot Gradle plugin (this module is a plain java-library), the
// configuration processor only sees the compiler's class output, so point it at
// src/main/resources to merge additional-spring-configuration-metadata.json.
tasks.compileJava {
    inputs.dir("src/main/resources")
    options.compilerArgs.add(
        "-Aorg.springframework.boot.configurationprocessor.additionalMetadataLocations=" +
            layout.projectDirectory.dir("src/main/resources").asFile.absolutePath
    )
}
