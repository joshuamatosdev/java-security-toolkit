// Plugin versions are declared once here; the bff and service subprojects apply them without
// versions. The example is a standalone composite build: the repository root is included as a
// source build, so the toolkit artifacts resolve from the current checkout, not a publication.
plugins {
    id("org.springframework.boot") version "4.1.0" apply false
    id("io.spring.dependency-management") version "1.1.7" apply false
}
