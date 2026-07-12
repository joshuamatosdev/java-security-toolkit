import io.spring.gradle.dependencymanagement.dsl.DependencyManagementExtension
import org.gradle.api.artifacts.VersionCatalogsExtension
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

val libraries = rootProject.extensions.getByType<VersionCatalogsExtension>().named("libs")
val assertjCore = libraries.findLibrary("assertj-core").orElseThrow()
val junitBom = libraries.findLibrary("junit-bom").orElseThrow()
val junitJupiter = libraries.findLibrary("junit-jupiter").orElseThrow()
val junitJupiterApi = libraries.findLibrary("junit-jupiter-api").orElseThrow()
val junitJupiterEngine = libraries.findLibrary("junit-jupiter-engine").orElseThrow()
val junitPlatformLauncher = libraries.findLibrary("junit-platform-launcher").orElseThrow()
val commonsCompressVersion = libraries.findVersion("commonsCompress").orElseThrow().requiredVersion
val commonsLang3Version = libraries.findVersion("commonsLang3").orElseThrow().requiredVersion
val nettyVersion = libraries.findVersion("netty").orElseThrow().requiredVersion
val postgresqlVersion = libraries.findVersion("postgresql").orElseThrow().requiredVersion
val springBootVersion = libraries.findVersion("springBoot").orElseThrow().requiredVersion
val testcontainersVersion = libraries.findVersion("testcontainers").orElseThrow().requiredVersion
val tomcatVersion = libraries.findVersion("tomcat").orElseThrow().requiredVersion

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

val frameworkFreeRuntimeAllowedGroups = mapOf(
    ":shared" to setOf("io.github.joshuamatosdev.security", "org.jspecify"),
    ":authorization" to setOf(
        "io.github.joshuamatosdev.security",
        "org.jspecify",
        "org.slf4j"
    )
)

val securityPinnedDependencyVersions = mapOf(
    ":edge" to mapOf(
        "runtimeClasspath" to mapOf(
            "io.netty:netty-codec-base" to nettyVersion,
            "io.netty:netty-codec-dns" to nettyVersion,
            "io.netty:netty-codec-http" to nettyVersion,
            "io.netty:netty-codec-http2" to nettyVersion,
            "io.netty:netty-handler-proxy" to nettyVersion
        )
    ),
    ":edge-spring-boot-starter" to mapOf(
        "runtimeClasspath" to mapOf(
            "io.netty:netty-codec-base" to nettyVersion,
            "io.netty:netty-codec-dns" to nettyVersion,
            "io.netty:netty-codec-http" to nettyVersion,
            "io.netty:netty-codec-http2" to nettyVersion,
            "io.netty:netty-handler-proxy" to nettyVersion
        )
    ),
    ":authorization-showcase" to mapOf(
        "runtimeClasspath" to mapOf(
            "org.apache.tomcat.embed:tomcat-embed-core" to tomcatVersion,
            "org.apache.tomcat.embed:tomcat-embed-websocket" to tomcatVersion,
            "org.postgresql:postgresql" to postgresqlVersion
        ),
        "testRuntimeClasspath" to mapOf(
            "org.apache.commons:commons-compress" to commonsCompressVersion,
            "org.apache.commons:commons-lang3" to commonsLang3Version
        )
    ),
    ":tenant-isolation" to mapOf(
        "runtimeClasspath" to mapOf(
            "org.postgresql:postgresql" to postgresqlVersion
        ),
        "testRuntimeClasspath" to mapOf(
            "org.apache.commons:commons-compress" to commonsCompressVersion,
            "org.apache.commons:commons-lang3" to commonsLang3Version
        )
    ),
    ":tenant-isolation-spring-boot-starter" to mapOf(
        "runtimeClasspath" to mapOf(
            "org.postgresql:postgresql" to postgresqlVersion
        )
    )
)

when (project.path) {
    ":edge", ":edge-spring-boot-starter" -> extra["netty.version"] = nettyVersion
    ":authorization-showcase" -> extra["tomcat.version"] = tomcatVersion
}

if (project.path in setOf(":tenant-isolation", ":authorization-showcase")) {
    extra["commons-lang3.version"] = commonsLang3Version
}

if (project.path in setOf(":tenant-isolation-spring-boot-starter", ":authorization-showcase")) {
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
                    name.set("Java Security Toolkit ${project.name}")
                    description.set(
                        "Production-oriented Java security architecture module from the Java Security Toolkit."
                    )
                    url.set("https://github.com/joshuamatosdev/java-security-toolkit")
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
                        connection.set("scm:git:https://github.com/joshuamatosdev/java-security-toolkit.git")
                        developerConnection.set(
                            "scm:git:ssh://git@github.com/joshuamatosdev/java-security-toolkit.git"
                        )
                        url.set("https://github.com/joshuamatosdev/java-security-toolkit")
                    }
                    issueManagement {
                        system.set("GitHub Issues")
                        url.set("https://github.com/joshuamatosdev/java-security-toolkit/issues")
                    }
                }
            }
        }
    }

    if (project.path in jspecifyPublicApiDependencies) {
        val assertJSpecifyPublicApiDependencyIsCompileScoped =
            tasks.register("assertJSpecifyPublicApiDependencyIsCompileScoped") {
                description =
                    "Fails if JSpecify is not compile-scoped in a publication whose public API exposes its annotations."
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
                    "Fails if this module's runtime closure gains a dependency outside its framework-free allow-list."
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
                    "Fails if a security-pinned dependency drifts in a resolved configuration."
                doLast {
                    expectedByConfiguration.forEach { (configurationName, expectedVersions) ->
                        val selectedVersions = configurations
                            .getByName(configurationName)
                            .incoming
                            .resolutionResult
                            .allComponents
                            .mapNotNull { component -> component.moduleVersion }
                            .associate { module ->
                                "${module.group}:${module.name}" to module.version
                            }

                        val mismatches = expectedVersions
                            .filter { (coordinate, expectedVersion) ->
                                selectedVersions[coordinate] != expectedVersion
                            }
                            .map { (coordinate, expectedVersion) ->
                                "$coordinate expected $expectedVersion, selected " +
                                    (selectedVersions[coordinate] ?: "missing")
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
    extensions.configure<DependencyManagementExtension>("dependencyManagement") {
        imports {
            mavenBom("org.springframework.boot:spring-boot-dependencies:$springBootVersion")

            if (project.path in setOf(":tenant-isolation", ":authorization", ":authorization-showcase")) {
                mavenBom("org.testcontainers:testcontainers-bom:$testcontainersVersion")
            }
        }
    }
}

plugins.withId("org.cyclonedx.bom") {
    val cyclonedxDirectBom =
        tasks.named<org.cyclonedx.gradle.CyclonedxDirectTask>("cyclonedxDirectBom") {
            includeConfigs = listOf("runtimeClasspath")
            jsonOutput.set(file("build/reports/bom.json"))
            xmlOutput.unsetConvention()
            schemaVersion = org.cyclonedx.Version.VERSION_15
            projectType = org.cyclonedx.model.Component.Type.LIBRARY
        }

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
            description = "Fails if the plain library jar bundles application configuration."
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
            description = "Fails if a Spring Boot library publication uses pom packaging."
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
                    "Fails if a Spring Boot library's public API dependencies are not compile-scoped in its POM."
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

fun dependencyScope(pomText: String, artifactId: String): String? {
    val dependencyBlock =
        Regex(
            "<dependency>[\\s\\S]*?<artifactId>${Regex.escape(artifactId)}</artifactId>[\\s\\S]*?</dependency>"
        ).find(pomText)?.value ?: return null
    return Regex("<scope>([^<]+)</scope>")
        .find(dependencyBlock)
        ?.groupValues
        ?.get(1)
        ?: "compile"
}
