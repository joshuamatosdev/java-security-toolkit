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
include("layered-authorization")
include("layered-authorization-spring-boot-starter")
include("layered-authorization-testkit")
include("edge-perimeter")
include("edge-perimeter-spring-boot-starter")
include("edge-perimeter-testkit")
include("supply-chain")
include("supply-chain-testkit")
include("crypto-agility")
include("crypto-agility-spring-boot-starter")
include("crypto-agility-testkit")
include("shared")
include("shared-testkit")
