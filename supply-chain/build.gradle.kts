plugins {
    `java-library`
}

java {
    toolchain { languageVersion = JavaLanguageVersion.of(21) }
}

dependencies {
    api(project(":supply-chain-core"))
}
