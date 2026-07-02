import org.gradle.api.plugins.JavaPluginExtension
import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.tasks.javadoc.Javadoc
import org.gradle.api.tasks.bundling.Jar
import org.gradle.api.tasks.testing.Test
import org.gradle.external.javadoc.StandardJavadocDocletOptions
import org.gradle.jvm.toolchain.JavaLanguageVersion
import org.gradle.plugins.signing.SigningExtension
import org.gradle.testing.jacoco.tasks.JacocoReport

plugins {
    base
    // Gradle-built-in aggregation (no external plugin): merges every module's JaCoCo execution
    // data into one repo-wide report at build/reports/jacoco/testCodeCoverageReport/.
    `jacoco-report-aggregation`
    alias(libs.plugins.spring.dep.management) apply false
    alias(libs.plugins.cyclonedx.bom) apply false
    alias(libs.plugins.owasp.dependencycheck)
}

reporting {
    reports {
        create<org.gradle.testing.jacoco.plugins.JacocoCoverageReport>("testCodeCoverageReport") {
            testSuiteName = "test"
        }
    }
}

dependencies {
    // The aggregation scope resolves each module's runtime graph at the root, where Spring's
    // dependency-management plugin is not applied — supply the same Boot BOM so the modules'
    // version-less Boot coordinates resolve identically.
    jacocoAggregation(platform("org.springframework.boot:spring-boot-dependencies:${libs.versions.springBoot.get()}"))
    subprojects.forEach { jacocoAggregation(it) }
}

// Repo-wide CVE gate. `dependencyCheckAggregate` scans every subproject's resolved closure —
// including the Spring Boot, WebFlux, Netty, Tomcat, and PostgreSQL runtime dependencies a consumer
// actually ships, not only supply-chain's. It is deliberately NOT wired into `check`: the NVD
// feed needs network access and an API key, which would break the offline clean-clone build
// contract. CI runs it as a scheduled / on-demand job with NVD_API_KEY (see ADR-0005).
dependencyCheck {
    failBuildOnCVSS = 7.0f
    formats = listOf("HTML", "JSON")
}

val bootLibraryPublicApiDependencies = mapOf(
    ":edge" to setOf(
        "spring-boot-starter-webflux",
        "spring-boot-starter-oauth2-client",
        "spring-boot-starter-oauth2-resource-server"
    ),
    ":tenant-isolation" to setOf("spring-boot-starter-data-jpa")
)

val jspecifyPublicApiDependencies = setOf(
    ":authorization",
    ":tenant-isolation",
    ":shared",
    ":supply-chain"
)

// The authorization split's promise — and shared's stronger one — as an executable check: the
// runtime closure of these library modules must stay framework-free. A group allowlist rather
// than a framework denylist, so any new transitive dependency fails loudly until it is judged.
val frameworkFreeRuntimeAllowedGroups = mapOf(
    ":shared" to setOf("io.github.joshuamatosdev.security", "org.jspecify"),
    ":authorization" to setOf("io.github.joshuamatosdev.security", "org.jspecify", "org.slf4j")
)

val pinnedCommonsCompressVersion = libs.versions.commonsCompress.get()
val pinnedCommonsLang3Version = libs.versions.commonsLang3.get()
val pinnedNettyVersion = libs.versions.netty.get()
val pinnedPostgresqlVersion = libs.versions.postgresql.get()
val pinnedTomcatVersion = libs.versions.tomcat.get()

val securityPinnedDependencyVersions = mapOf(
    ":edge" to mapOf(
        "runtimeClasspath" to mapOf(
            "io.netty:netty-codec" to pinnedNettyVersion,
            "io.netty:netty-codec-dns" to pinnedNettyVersion,
            "io.netty:netty-codec-http" to pinnedNettyVersion,
            "io.netty:netty-codec-http2" to pinnedNettyVersion,
            "io.netty:netty-handler-proxy" to pinnedNettyVersion
        )
    ),
    ":edge-spring-boot-starter" to mapOf(
        "runtimeClasspath" to mapOf(
            "io.netty:netty-codec" to pinnedNettyVersion,
            "io.netty:netty-codec-dns" to pinnedNettyVersion,
            "io.netty:netty-codec-http" to pinnedNettyVersion,
            "io.netty:netty-codec-http2" to pinnedNettyVersion,
            "io.netty:netty-handler-proxy" to pinnedNettyVersion
        )
    ),
    // The decision core and its starter carry no web server or database driver anymore; the
    // showcase application owns that CVE surface.
    ":authorization-showcase" to mapOf(
        "runtimeClasspath" to mapOf(
            "org.apache.tomcat.embed:tomcat-embed-core" to pinnedTomcatVersion,
            "org.apache.tomcat.embed:tomcat-embed-websocket" to pinnedTomcatVersion,
            "org.postgresql:postgresql" to pinnedPostgresqlVersion
        ),
        "testRuntimeClasspath" to mapOf(
            "org.apache.commons:commons-compress" to pinnedCommonsCompressVersion,
            "org.apache.commons:commons-lang3" to pinnedCommonsLang3Version
        )
    ),
    ":tenant-isolation" to mapOf(
        "runtimeClasspath" to mapOf(
            "org.postgresql:postgresql" to pinnedPostgresqlVersion
        ),
        "testRuntimeClasspath" to mapOf(
            "org.apache.commons:commons-compress" to pinnedCommonsCompressVersion,
            "org.apache.commons:commons-lang3" to pinnedCommonsLang3Version
        )
    ),
    ":tenant-isolation-spring-boot-starter" to mapOf(
        "runtimeClasspath" to mapOf(
            "org.postgresql:postgresql" to pinnedPostgresqlVersion
        )
    )
)

allprojects {
    group = "io.github.joshuamatosdev.security"
    version = "0.1.0-SNAPSHOT"
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
    description = "Checks repository text files for LF endings, trailing whitespace, final newline, and credential-shaped URL user-info."
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

val assertjCore = libs.assertj.core
val junitBom = libs.junit.bom
val junitJupiter = libs.junit.jupiter
val junitJupiterApi = libs.junit.jupiter.api
val junitJupiterEngine = libs.junit.jupiter.engine
val junitPlatformLauncher = libs.junit.platform.launcher
val commonsLang3Version = libs.versions.commonsLang3.get()
val nettyVersion = libs.versions.netty.get()
val postgresqlVersion = libs.versions.postgresql.get()
val springBootVersion = libs.versions.springBoot.get()
val testcontainersVersion = libs.versions.testcontainers.get()
val tomcatVersion = libs.versions.tomcat.get()

subprojects {
    when (project.path) {
        ":edge",
        ":edge-spring-boot-starter" ->
            extra["netty.version"] = nettyVersion

        ":authorization-showcase" ->
            extra["tomcat.version"] = tomcatVersion
    }

    if (project.path in setOf(":tenant-isolation", ":authorization-showcase")) {
        extra["commons-lang3.version"] = commonsLang3Version
    }

    if (project.path in setOf(
            ":tenant-isolation-spring-boot-starter",
            ":authorization-showcase"
        )) {
        extra["postgresql.version"] = postgresqlVersion
    }

    plugins.withId("java") {
        apply(plugin = "maven-publish")
        apply(plugin = "signing")
        apply(plugin = "jacoco")

        extensions.configure<JavaPluginExtension>("java") {
            toolchain {
                languageVersion = JavaLanguageVersion.of(21)
            }
            withSourcesJar()
            withJavadocJar()
        }

        dependencies {
            add("testImplementation", platform(junitBom))
            add("testImplementation", junitJupiter)
            add("testImplementation", assertjCore)
            add("testRuntimeOnly", junitPlatformLauncher)
        }

        tasks.named<Test>("test") {
            useJUnitPlatform()
            finalizedBy(tasks.named("jacocoTestReport"))
        }

        tasks.named<JacocoReport>("jacocoTestReport") {
            dependsOn(tasks.named("test"))
            reports {
                xml.required = true
                html.required = true
                csv.required = false
            }
        }

        tasks.withType<Javadoc>().configureEach {
            (options as StandardJavadocDocletOptions).addStringOption("Xdoclint:none", "-quiet")
        }

        // Maven Central requires signed artifacts. Signing engages only when the key is present
        // in the environment (CI release secrets); local and offline builds stay unaffected and
        // publishToMavenLocal never demands a key.
        extensions.configure<SigningExtension>("signing") {
            val signingKey = System.getenv("SIGNING_KEY")
            val signingPassword = System.getenv("SIGNING_PASSWORD")
            if (!signingKey.isNullOrBlank()) {
                useInMemoryPgpKeys(signingKey, signingPassword)
                sign(extensions.getByType(PublishingExtension::class.java).publications)
            }
        }

        extensions.configure<PublishingExtension>("publishing") {
            publications {
                create<MavenPublication>("mavenJava") {
                    from(components["java"])
                    versionMapping {
                        usage("java-api") {
                            fromResolutionOf("runtimeClasspath")
                        }
                        usage("java-runtime") {
                            fromResolutionResult()
                        }
                    }

                    pom {
                        name.set("Bulwark ${project.name}")
                        description.set(
                            "Production-oriented Java security architecture module from Bulwark."
                        )
                        url.set("https://github.com/joshuamatosdev/bulwark")
                        licenses {
                            license {
                                name.set("Apache License, Version 2.0")
                                url.set("https://www.apache.org/licenses/LICENSE-2.0")
                            }
                        }
                        developers {
                            developer {
                                id.set("joshuamatosdev")
                                name.set("Joshua Matos")
                                organization.set("DoctrineOne Industries")
                            }
                        }
                        scm {
                            connection.set("scm:git:https://github.com/joshuamatosdev/bulwark.git")
                            developerConnection.set("scm:git:ssh://git@github.com/joshuamatosdev/bulwark.git")
                            url.set("https://github.com/joshuamatosdev/bulwark")
                        }
                        issueManagement {
                            system.set("GitHub Issues")
                            url.set("https://github.com/joshuamatosdev/bulwark/issues")
                        }
                    }
                }
            }
        }

        if (project.path in jspecifyPublicApiDependencies) {
            val assertJSpecifyPublicApiDependencyIsCompileScoped =
                tasks.register("assertJSpecifyPublicApiDependencyIsCompileScoped") {
                    description =
                        "Fails the build if JSpecify is not compile-scoped in the published POM of a module that exposes it in public API annotations."
                    val pomFile = layout.buildDirectory.file("publications/mavenJava/pom-default.xml")

                    dependsOn(tasks.named("generatePomFileForMavenJavaPublication"))
                    inputs.file(pomFile)

                    doLast {
                        val pomText = pomFile.get().asFile.readText()
                        if (dependencyScope(pomText, "jspecify") != "compile") {
                            throw GradleException(
                                "Publication ${project.path} must compile-scope JSpecify because it appears in public API annotations"
                            )
                        }
                    }
                }

            tasks.named("check") {
                dependsOn(assertJSpecifyPublicApiDependencyIsCompileScoped)
            }
        }

        frameworkFreeRuntimeAllowedGroups[project.path]?.let { allowedGroups ->
            val assertFrameworkFreeRuntimeClasspath =
                tasks.register("assertFrameworkFreeRuntimeClasspath") {
                    description =
                        "Fails the build if this module's runtime closure gains a dependency group outside its framework-free allowlist."
                    doLast {
                        val offending = configurations
                            .getByName("runtimeClasspath")
                            .incoming
                            .resolutionResult
                            .allComponents
                            .mapNotNull { component -> component.moduleVersion }
                            .map { module -> "${module.group}:${module.name}" }
                            .filterNot { coordinate ->
                                allowedGroups.any { group -> coordinate.startsWith("$group:") }
                            }

                        if (offending.isNotEmpty()) {
                            throw GradleException(
                                "${project.path} must stay framework-free at runtime; " +
                                    "unexpected dependencies: ${offending.joinToString()}"
                            )
                        }
                    }
                }

            tasks.named("check") {
                dependsOn(assertFrameworkFreeRuntimeClasspath)
            }
        }

        securityPinnedDependencyVersions[project.path]?.let { expectedByConfiguration ->
            val assertSecurityPinnedDependencyVersions =
                tasks.register("assertSecurityPinnedDependencyVersions") {
                    description =
                        "Fails the build if a security-pinned dependency version has drifted from the version pinned for this module's resolved configurations."
                    doLast {
                        expectedByConfiguration.forEach { (configurationName, expectedVersions) ->
                            val selectedVersions = configurations
                                .getByName(configurationName)
                                .incoming
                                .resolutionResult
                                .allComponents
                                .mapNotNull { component -> component.moduleVersion }
                                .associate { module -> "${module.group}:${module.name}" to module.version }

                            val mismatches = expectedVersions
                                .filter { (coordinate, expectedVersion) ->
                                    selectedVersions[coordinate] != expectedVersion
                                }
                                .map { (coordinate, expectedVersion) ->
                                    "$coordinate expected $expectedVersion, selected ${selectedVersions[coordinate] ?: "missing"}"
                                }

                            if (mismatches.isNotEmpty()) {
                                throw GradleException(
                                    "Security-pinned dependency versions drifted in ${project.path} " +
                                        "$configurationName: ${mismatches.joinToString()}"
                                )
                            }
                        }
                    }
                }

            tasks.named("check") {
                dependsOn(assertSecurityPinnedDependencyVersions)
            }
        }
    }

    plugins.withId("java-library") {
        if (project.name.endsWith("testkit")) {
            dependencies {
                add("api", junitJupiterApi)
                add("api", assertjCore)
                add("testRuntimeOnly", junitJupiterEngine)
            }
        }
    }

    plugins.withId("io.spring.dependency-management") {
        extensions.configure<io.spring.gradle.dependencymanagement.dsl.DependencyManagementExtension>(
            "dependencyManagement"
        ) {
            imports {
                mavenBom("org.springframework.boot:spring-boot-dependencies:$springBootVersion")

                if (project.path in setOf(":tenant-isolation", ":authorization")) {
                    mavenBom("org.testcontainers:testcontainers-bom:$testcontainersVersion")
                }
            }
        }
    }

    plugins.withId("org.cyclonedx.bom") {
        val cyclonedxDirectBom = tasks.named<org.cyclonedx.gradle.CyclonedxDirectTask>("cyclonedxDirectBom") {
            includeConfigs = listOf("runtimeClasspath")
            jsonOutput.set(file("build/reports/bom.json"))
            xmlOutput.unsetConvention()
            schemaVersion = org.cyclonedx.Version.VERSION_15
            projectType = org.cyclonedx.model.Component.Type.LIBRARY
        }

        // Realize during configuration so the plugin's outgoing artifact variant exists before
        // other projects consume this module.
        cyclonedxDirectBom.get()

        tasks.named("check") {
            dependsOn(cyclonedxDirectBom)
        }
    }

    plugins.withId("org.springframework.boot") {
        val plainJar = tasks.named<Jar>("jar")
        val executableJar = tasks.named<Jar>("bootJar")

        executableJar.configure {
            archiveClassifier.set("boot")
        }

        plainJar.configure {
            archiveClassifier.set("")
            exclude("application.yaml", "application-*.yaml")
        }

        val assertPlainJarDoesNotShipApplicationConfiguration =
            tasks.register("assertPlainJarDoesNotShipApplicationConfiguration") {
                description =
                    "Fails the build if the plain (non-boot) library jar bundles application.yaml configuration."
                dependsOn(plainJar)
                inputs.file(plainJar.flatMap { it.archiveFile })

                doLast {
                    val leakedApplicationConfiguration = zipTree(plainJar.get().archiveFile)
                        .matching { include("application.yaml", "application-*.yaml") }
                        .files
                        .map { it.name }
                        .sorted()

                    if (leakedApplicationConfiguration.isNotEmpty()) {
                        throw GradleException(
                            "Plain ${project.path} jar must not ship application configuration: " +
                                leakedApplicationConfiguration.joinToString()
                        )
                    }
                }
            }

        tasks.named("check") {
            dependsOn(assertPlainJarDoesNotShipApplicationConfiguration)
        }

        val assertBootLibraryPublicationHasJarPackaging =
            tasks.register("assertBootLibraryPublicationHasJarPackaging") {
                description =
                    "Fails the build if this Spring Boot library publication declares pom packaging instead of a jar artifact."
                val pomFile = layout.buildDirectory.file("publications/mavenJava/pom-default.xml")

                dependsOn(tasks.named("generatePomFileForMavenJavaPublication"))
                inputs.file(pomFile)

                doLast {
                    val pomText = pomFile.get().asFile.readText()
                    if (pomText.contains("<packaging>pom</packaging>")) {
                        throw GradleException(
                            "Spring Boot library publication ${project.path} must publish a jar artifact, not pom packaging"
                        )
                    }
                }
            }

        tasks.named("check") {
            dependsOn(assertBootLibraryPublicationHasJarPackaging)
        }

        val expectedCompileScopedPublicApiDependencies =
            bootLibraryPublicApiDependencies[project.path].orEmpty()
        if (expectedCompileScopedPublicApiDependencies.isNotEmpty()) {
            val assertBootLibraryPublicApiDependenciesAreCompileScoped =
                tasks.register("assertBootLibraryPublicApiDependenciesAreCompileScoped") {
                    description =
                        "Fails the build if this Spring Boot library's public-API dependencies are not compile-scoped in the published POM."
                    val pomFile = layout.buildDirectory.file("publications/mavenJava/pom-default.xml")

                    dependsOn(tasks.named("generatePomFileForMavenJavaPublication"))
                    inputs.file(pomFile)

                    doLast {
                        val pomText = pomFile.get().asFile.readText()
                        val runtimeScopedDependencies = expectedCompileScopedPublicApiDependencies
                            .filter { artifactId -> dependencyScope(pomText, artifactId) != "compile" }

                        if (runtimeScopedDependencies.isNotEmpty()) {
                            throw GradleException(
                                "Spring Boot library publication ${project.path} must compile-scope public API dependencies: " +
                                    runtimeScopedDependencies.joinToString()
                            )
                        }
                    }
                }

            tasks.named("check") {
                dependsOn(assertBootLibraryPublicApiDependenciesAreCompileScoped)
            }
        }
    }
}

fun dependencyScope(pomText: String, artifactId: String): String? {
    val dependencyBlock = Regex("<dependency>[\\s\\S]*?<artifactId>${Regex.escape(artifactId)}</artifactId>[\\s\\S]*?</dependency>")
        .find(pomText)
        ?.value
        ?: return null
    return Regex("<scope>([^<]+)</scope>")
        .find(dependencyBlock)
        ?.groupValues
        ?.get(1)
        ?: "compile"
}
