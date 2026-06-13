# Base-image-pin policy: every external FROM is pinned by an immutable @sha256 digest, never a
# floating tag. A tag like `21-jre` is mutable — the registry can repoint it at new content between
# two builds — so a reproducible, tamper-evident build pins the content digest instead. BaseImagePolicy
# + BaseImagePolicyTest fail the build if any external FROM here loses its digest.
#
# Refresh deliberately with:
#   docker buildx imagetools inspect eclipse-temurin:21-jre --format '{{.Manifest.Digest}}'

FROM eclipse-temurin:21-jre@sha256:010e0a06bd4e0184dec58626afb3ba727b42c56c91b977e2f0a9e0837e0fa3fb AS runtime

WORKDIR /app
COPY build/libs/*.jar app.jar
# Run as a non-root, fixed UID/GID — no shell, no package manager in the runtime layer.
USER 1000:1000
ENTRYPOINT ["java", "-jar", "app.jar"]
