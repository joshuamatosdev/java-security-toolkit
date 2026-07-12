import org.gradle.api.artifacts.VersionCatalogsExtension

plugins {
    base
    `jacoco-report-aggregation`
    id("org.owasp.dependencycheck")
}

val libraries = extensions.getByType<VersionCatalogsExtension>().named("libs")
val springBootVersion = libraries.findVersion("springBoot").orElseThrow().requiredVersion

allprojects {
    group = "io.github.joshuamatosdev.security"
    version = "0.1.0-SNAPSHOT"
}

subprojects {
    pluginManager.apply("security.toolkit.project-conventions")
}

reporting {
    reports {
        create<org.gradle.testing.jacoco.plugins.JacocoCoverageReport>("testCodeCoverageReport") {
            testSuiteName = "test"
        }
    }
}

dependencies {
    jacocoAggregation(platform("org.springframework.boot:spring-boot-dependencies:$springBootVersion"))
    subprojects.forEach { jacocoAggregation(it) }
}

// The network-backed CVE scan is intentionally separate from `check`; CI invokes the aggregate
// task with its vulnerability-feed credentials.
dependencyCheck {
    failBuildOnCVSS = 7.0f
    formats = listOf("HTML", "JSON")
}

val releaseTextIncludes = listOf(
    "**/*.java",
    "**/*.kt",
    "**/*.kts",
    "**/*.properties",
    "**/*.sql",
    "**/*.toml",
    "**/*.yaml",
    "**/*.yml",
    "**/*.md",
    ".editorconfig",
    ".gitattributes",
    ".gitignore",
    "LICENSE",
    "NOTICE",
    "gradlew",
    "gradlew.bat"
)

val credentialLikeUrl = Regex("""https?://[^\s/@:]+:[^\s/@]*@""")

val checkRepositoryTextFiles = tasks.register("checkRepositoryTextFiles") {
    description =
        "Checks repository text files for LF endings, trailing whitespace, final newline, and credential-shaped URL user-info."
    group = "verification"

    val textFiles = fileTree(rootDir) {
        releaseTextIncludes.forEach { include(it) }
        exclude(
            "**/.git/**",
            "**/.gradle/**",
            "**/.idea/**",
            "**/build/**",
            "**/out/**",
            "**/target/**"
        )
    }

    inputs.files(textFiles)

    doLast {
        val violations = mutableListOf<String>()
        textFiles.files.sortedBy { it.relativeTo(rootDir).invariantSeparatorsPath }.forEach { file ->
            val relativePath = file.relativeTo(rootDir).invariantSeparatorsPath
            val text = file.readText(Charsets.UTF_8)

            if (!relativePath.endsWith(".bat") && text.contains('\r')) {
                violations.add("$relativePath must use LF line endings")
            }
            if (text.isNotEmpty() && !text.endsWith('\n')) {
                violations.add("$relativePath must end with a newline")
            }
            text.lineSequence().forEachIndexed { index, line ->
                if (line.endsWith(" ") || line.endsWith("\t")) {
                    violations.add("$relativePath:${index + 1} has trailing whitespace")
                }
            }
            if (credentialLikeUrl.containsMatchIn(text)) {
                violations.add("$relativePath contains credential-shaped URL user-info")
            }
        }

        if (violations.isNotEmpty()) {
            throw GradleException(
                "Repository text hygiene check failed:\n" + violations.joinToString("\n")
            )
        }
    }
}

tasks.named("check") {
    dependsOn(checkRepositoryTextFiles)
}
