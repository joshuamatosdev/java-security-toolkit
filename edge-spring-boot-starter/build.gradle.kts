plugins {
    `java-library`
    id("io.spring.dependency-management")
}

dependencies {
    api(project(":edge"))
    implementation("org.springframework.boot:spring-boot")
    implementation("org.springframework.boot:spring-boot-autoconfigure")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
}
