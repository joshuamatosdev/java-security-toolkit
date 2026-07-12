plugins {
    `java-library`
    id("io.spring.dependency-management")
}

dependencies {
    api(project(":authorization"))
    implementation("org.springframework.boot:spring-boot")
    implementation("org.springframework.boot:spring-boot-autoconfigure")
    // Optional web surface: only the 403 denial advice needs spring-web, and it activates only in
    // servlet web applications. Non-web adopters keep a web-free classpath.
    compileOnly("org.springframework:spring-web")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework:spring-webmvc")
    testImplementation("jakarta.servlet:jakarta.servlet-api")
}
