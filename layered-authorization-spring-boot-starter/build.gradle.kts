plugins {
    `java-library`
    alias(libs.plugins.spring.dep.management)
}

dependencies {
    api(project(":layered-authorization"))
    implementation("org.springframework.boot:spring-boot")
    implementation("org.springframework.boot:spring-boot-autoconfigure")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
}
