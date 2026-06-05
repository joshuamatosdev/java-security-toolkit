plugins {
    java
    id("org.springframework.boot") version "3.5.6"
    id("io.spring.dependency-management") version "1.1.7"
}

java {
    toolchain { languageVersion = JavaLanguageVersion.of(21) }
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter")
    implementation("io.github.joshuamatosdev.security:crypto-agility-spring-boot-starter:0.1.0-SNAPSHOT")
}
