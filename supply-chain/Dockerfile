# Base-image-pin policy: every external FROM is pinned by an immutable @sha256 digest, never a
# floating tag. A tag like `21-jre` is mutable — the registry can repoint it at new content between
# two builds — so a reproducible, tamper-evident build pins the content digest instead. BaseImagePolicy
# + BaseImagePolicyTest fail the build if any external FROM here loses its digest.
#
# The digest below is illustrative for the showcase. Refresh it against the registry before any real
# deployment:
#   docker buildx imagetools inspect eclipse-temurin:21-jre --format '{{.Manifest.Digest}}'

FROM eclipse-temurin:21-jre@sha256:9c7f1e3b2a4d6c8e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70 AS runtime

WORKDIR /app
COPY build/libs/*.jar app.jar
# Run as a non-root, fixed UID/GID — no shell, no package manager in the runtime layer.
USER 1000:1000
ENTRYPOINT ["java", "-jar", "app.jar"]
