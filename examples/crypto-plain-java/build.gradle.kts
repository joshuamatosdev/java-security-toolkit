plugins {
    application
}

java {
    toolchain { languageVersion = JavaLanguageVersion.of(21) }
}

dependencies {
    implementation("io.github.joshuamatosdev.security:crypto:0.1.0-SNAPSHOT")
}

application {
    mainClass.set("example.PlainJavaCryptoExample")
}
