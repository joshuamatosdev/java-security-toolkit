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
