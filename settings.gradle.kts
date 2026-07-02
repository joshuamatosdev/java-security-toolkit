dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

rootProject.name = "bulwark"

// Modules are added as they land (one spec → plan → build cycle each).
include("tenant-isolation")
include("tenant-isolation-spring-boot-starter")
include("tenant-isolation-testkit")
include("authorization")
include("authorization-spring-boot-starter")
include("authorization-testkit")
include("edge")
include("edge-spring-boot-starter")
include("edge-testkit")
include("supply-chain")
include("supply-chain-testkit")
include("crypto")
include("crypto-spring-boot-starter")
include("crypto-testkit")
include("shared")
include("shared-testkit")
