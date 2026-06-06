import org.gradle.api.plugins.JavaPluginExtension
import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.tasks.javadoc.Javadoc
import org.gradle.api.tasks.bundling.Jar
import org.gradle.external.javadoc.StandardJavadocDocletOptions

val bootLibraryPublicApiDependencies = mapOf(
    ":edge-perimeter" to setOf(
        "spring-boot-starter-webflux",
        "spring-boot-starter-oauth2-client",
        "spring-boot-starter-oauth2-resource-server"
    ),
    ":layered-authorization" to setOf(
        "spring-boot-starter-web",
        "spring-boot-starter-security",
        "spring-boot-starter-data-jpa"
    ),
    ":tenant-isolation" to setOf("spring-boot-starter-data-jpa")
)

val jspecifyPublicApiDependencies = setOf(
    ":layered-authorization",
    ":tenant-isolation",
    ":shared",
    ":supply-chain-core"
)

val pinnedCommonsCompressVersion = libs.versions.commonsCompress.get()
val pinnedCommonsLang3Version = libs.versions.commonsLang3.get()
val pinnedNettyVersion = libs.versions.netty.get()
val pinnedPostgresqlVersion = libs.versions.postgresql.get()
val pinnedTomcatVersion = libs.versions.tomcat.get()

val securityPinnedDependencyVersions = mapOf(
    ":edge-perimeter" to mapOf(
        "runtimeClasspath" to mapOf(
            "io.netty:netty-codec" to pinnedNettyVersion,
            "io.netty:netty-codec-dns" to pinnedNettyVersion,
            "io.netty:netty-codec-http" to pinnedNettyVersion,
            "io.netty:netty-codec-http2" to pinnedNettyVersion,
            "io.netty:netty-handler-proxy" to pinnedNettyVersion
        )
    ),
    ":edge-perimeter-spring-boot-starter" to mapOf(
        "runtimeClasspath" to mapOf(
            "io.netty:netty-codec" to pinnedNettyVersion,
            "io.netty:netty-codec-dns" to pinnedNettyVersion,
            "io.netty:netty-codec-http" to pinnedNettyVersion,
            "io.netty:netty-codec-http2" to pinnedNettyVersion,
            "io.netty:netty-handler-proxy" to pinnedNettyVersion
        )
    ),
    ":layered-authorization" to mapOf(
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
    ":layered-authorization-spring-boot-starter" to mapOf(
        "runtimeClasspath" to mapOf(
            "org.apache.tomcat.embed:tomcat-embed-core" to pinnedTomcatVersion,
            "org.apache.tomcat.embed:tomcat-embed-websocket" to pinnedTomcatVersion,
            "org.postgresql:postgresql" to pinnedPostgresqlVersion
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

subprojects {
    plugins.withId("java") {
        apply(plugin = "maven-publish")

        extensions.configure<JavaPluginExtension>("java") {
            withSourcesJar()
            withJavadocJar()
        }

        tasks.withType<Javadoc>().configureEach {
            (options as StandardJavadocDocletOptions).addStringOption("Xdoclint:none", "-quiet")
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
                        name.set("Project Glyptodon ${project.name}")
                        description.set(
                            "Production-oriented Java security architecture module from Project Glyptodon."
                        )
                        url.set("https://github.com/joshuamatosdev/project-glyptodon")
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
                            connection.set("scm:git:https://github.com/joshuamatosdev/project-glyptodon.git")
                            developerConnection.set("scm:git:ssh://git@github.com/joshuamatosdev/project-glyptodon.git")
                            url.set("https://github.com/joshuamatosdev/project-glyptodon")
                        }
                        issueManagement {
                            system.set("GitHub Issues")
                            url.set("https://github.com/joshuamatosdev/project-glyptodon/issues")
                        }
                    }
                }
            }
        }

        if (project.path in jspecifyPublicApiDependencies) {
            val assertJSpecifyPublicApiDependencyIsCompileScoped =
                tasks.register("assertJSpecifyPublicApiDependencyIsCompileScoped") {
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

        securityPinnedDependencyVersions[project.path]?.let { expectedByConfiguration ->
            val assertSecurityPinnedDependencyVersions =
                tasks.register("assertSecurityPinnedDependencyVersions") {
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
