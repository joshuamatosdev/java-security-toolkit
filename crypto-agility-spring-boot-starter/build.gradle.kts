plugins {
    `java-library`
    alias(libs.plugins.spring.dep.management)
    alias(libs.plugins.cyclonedx.bom)
}

dependencies {
    api(project(":crypto-agility"))

    implementation("org.springframework.boot:spring-boot")
    implementation("org.springframework.boot:spring-boot-autoconfigure")
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
}
