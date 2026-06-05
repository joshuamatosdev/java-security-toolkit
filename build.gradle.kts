import org.gradle.api.plugins.JavaPluginExtension
import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.tasks.javadoc.Javadoc
import org.gradle.external.javadoc.StandardJavadocDocletOptions

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
    }
}
