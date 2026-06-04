dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

rootProject.name = "glyptodon"

// Modules are added as they land (one spec → plan → build cycle each).
include("tenant-isolation")
include("layered-authorization")
include("edge-perimeter")
include("supply-chain")
include("crypto-agility")
include("shared")
