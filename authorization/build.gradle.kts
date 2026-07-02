plugins {
    `java-library`
    alias(libs.plugins.spring.dep.management)
}

dependencies {
    api(project(":shared"))
    api(libs.jspecify)
    implementation("org.slf4j:slf4j-api")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
}
