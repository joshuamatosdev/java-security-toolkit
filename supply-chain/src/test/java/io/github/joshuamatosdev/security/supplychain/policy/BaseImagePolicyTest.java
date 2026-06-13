package io.github.joshuamatosdev.security.supplychain.policy;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Proves the base-image-pin policy is enforced against the module's actual Dockerfile, and that the
 * pinned-vs-floating distinction the policy rests on is correct.
 *
 * <p>Why this is important to test: build trust checks only protect the system when generated
 * SBOMs and base-image pins are asserted continuously.
 */
class BaseImagePolicyTest {

  private final BaseImagePolicy policy = new BaseImagePolicy();
  private static final String VERIFIED_ECLIPSE_TEMURIN_21_JRE_REF =
      "eclipse-temurin:21-jre@sha256:010e0a06bd4e0184dec58626afb3ba727b42c56c91b977e2f0a9e0837e0fa3fb";

  @TempDir Path tempDir;

  private static Path dockerfile() {
    return Path.of(System.getProperty("dockerfile.path", "Dockerfile"));
  }

  @Test
  void theModuleDockerfilePinsEveryExternalBaseImage() {
    assertThat(policy.unpinnedExternalRefs(dockerfile()))
        .as("every external FROM must pin an immutable @sha256 digest, not a floating tag")
        .isEmpty();
  }

  @Test
  void theModuleDockerfileUsesAVerifiedRuntimeDigestNotAnIllustrativePlaceholder() throws IOException {
    assertThat(Files.readString(dockerfile()))
        .contains("FROM " + VERIFIED_ECLIPSE_TEMURIN_21_JRE_REF + " AS runtime")
        .doesNotContain("illustrative");
  }

  @Test
  void aFloatingTagIsNotConsideredPinned() {
    assertThat(policy.isDigestPinned("eclipse-temurin:21-jre")).isFalse();
  }

  @Test
  void absentImageReferenceIsNotConsideredPinned() {
    assertThat(policy.isDigestPinned(null)).isFalse();
  }

  @Test
  void aDigestReferenceIsConsideredPinned() {
    assertThat(policy.isDigestPinned("eclipse-temurin:21-jre@sha256:" + "a".repeat(64))).isTrue();
  }

  @Test
  void digestReferenceMustUseOciCanonicalLowercaseSha256Format() {
    assertThat(policy.isDigestPinned("eclipse-temurin:21-jre@SHA256:" + "a".repeat(64))).isFalse();
    assertThat(policy.isDigestPinned("eclipse-temurin:21-jre@sha256:" + "A".repeat(64))).isFalse();
  }

  @Test
  void edgePaddedDigestReferenceIsNotConsideredPinned() {
    assertThat(policy.isDigestPinned(" eclipse-temurin:21-jre@sha256:" + "a".repeat(64))).isFalse();
    assertThat(policy.isDigestPinned("eclipse-temurin:21-jre@sha256:" + "a".repeat(64) + " ")).isFalse();
  }

  @Test
  void whitespaceInsideDigestReferenceIsNotConsideredPinned() {
    assertThat(policy.isDigestPinned("eclipse-temurin:21 jre@sha256:" + "a".repeat(64))).isFalse();
  }

  @Test
  void controlCharacterInsideDigestReferenceIsNotConsideredPinned() {
    assertThat(policy.isDigestPinned("eclipse-temurin:21-jre\u0000@sha256:" + "a".repeat(64))).isFalse();
  }

  @Test
  void aShortOrNonHexDigestIsNotPinned() {
    assertThat(policy.isDigestPinned("img@sha256:abc")).isFalse();
    assertThat(policy.isDigestPinned("img@sha256:" + "z".repeat(64))).isFalse();
  }

  @Test
  void malformedUppercaseDigestReferenceIsReportedAsUnpinnedExternalImage() throws IOException {
    Path dockerfile =
        writeDockerfile(
            """
            FROM eclipse-temurin:21-jre@SHA256:%s AS runtime
            """
                .formatted("a".repeat(64)));

    assertThat(policy.unpinnedExternalRefs(dockerfile))
        .containsExactly("eclipse-temurin:21-jre@SHA256:" + "a".repeat(64));
  }

  @Test
  void forwardStageNameDoesNotExemptEarlierExternalImage() throws IOException {
    Path dockerfile =
        writeDockerfile(
            """
            FROM builder
            FROM eclipse-temurin:21-jre@sha256:%s AS builder
            """
                .formatted("a".repeat(64)));

    assertThat(policy.unpinnedExternalRefs(dockerfile)).containsExactly("builder");
  }

  @Test
  void priorStageNameExemptsInternalStageReference() throws IOException {
    Path dockerfile =
        writeDockerfile(
            """
            FROM eclipse-temurin:21-jre@sha256:%s AS builder
            FROM builder
            """
                .formatted("a".repeat(64)));

    assertThat(policy.unpinnedExternalRefs(dockerfile)).isEmpty();
  }

  @Test
  void stageReferencesFollowDockerCaseInsensitiveLookup() throws IOException {
    Path dockerfile =
        writeDockerfile(
            """
            FROM eclipse-temurin:21-jre@sha256:%s AS Builder
            FROM builder
            """
                .formatted("a".repeat(64)));

    assertThat(policy.unpinnedExternalRefs(dockerfile)).isEmpty();
  }

  @Test
  void copyAndRunMountStageReferencesFollowDockerCaseInsensitiveLookup() throws IOException {
    Path dockerfile =
        writeDockerfile(
            """
            FROM eclipse-temurin:21-jre@sha256:%s AS Builder
            FROM scratch
            COPY --from=builder /app /app
            RUN --mount=type=bind,from=builder,target=/builder,readonly true
            """
                .formatted("a".repeat(64)));

    assertThat(policy.unpinnedExternalRefs(dockerfile)).isEmpty();
  }

  @Test
  void inlineCommentAfterStageDeclarationDoesNotCreateAStageAlias() throws IOException {
    Path dockerfile =
        writeDockerfile(
            """
            FROM eclipse-temurin:21-jre@sha256:%s AS builder # build stage
            FROM builder
            """
                .formatted("a".repeat(64)));

    assertThat(policy.unpinnedExternalRefs(dockerfile)).containsExactly("builder");
  }

  @Test
  void stageNameInCommentDoesNotExemptExternalImageReference() throws IOException {
    Path dockerfile =
        writeDockerfile(
            """
            FROM eclipse-temurin:21-jre@sha256:%s # AS builder
            FROM builder
            """
                .formatted("a".repeat(64)));

    assertThat(policy.unpinnedExternalRefs(dockerfile)).containsExactly("builder");
  }

  @Test
  void externalImageSourceUsedByCopyFromMustBeDigestPinned() throws IOException {
    Path dockerfile =
        writeDockerfile(
            """
            FROM eclipse-temurin:21-jre@sha256:%s AS runtime
            COPY --from=nginx:latest /etc/nginx/nginx.conf /nginx.conf
            """
                .formatted("a".repeat(64)));

    assertThat(policy.unpinnedExternalRefs(dockerfile)).containsExactly("nginx:latest");
  }

  @Test
  void externalImageSourceUsedByRunMountFromMustBeDigestPinned() throws IOException {
    Path dockerfile =
        writeDockerfile(
            """
            FROM eclipse-temurin:21-jre@sha256:%s AS runtime
            RUN --mount=type=bind,from=nginx:latest,target=/nginx,readonly cp /nginx/conf /tmp/conf
            """
                .formatted("a".repeat(64)));

    assertThat(policy.unpinnedExternalRefs(dockerfile)).containsExactly("nginx:latest");
  }

  @Test
  void externalCopyFromOnContinuedInstructionMustBeDigestPinned() throws IOException {
    Path dockerfile =
        writeDockerfile(
            """
            FROM eclipse-temurin:21-jre@sha256:%s AS runtime
            COPY \\
              --from=nginx:latest \\
              /etc/nginx/nginx.conf /nginx.conf
            """
                .formatted("a".repeat(64)));

    assertThat(policy.unpinnedExternalRefs(dockerfile)).containsExactly("nginx:latest");
  }

  @Test
  void externalRunMountFromOnContinuedInstructionMustBeDigestPinned() throws IOException {
    Path dockerfile =
        writeDockerfile(
            """
            FROM eclipse-temurin:21-jre@sha256:%s AS runtime
            RUN \\
              --mount=type=bind,from=nginx:latest,target=/nginx,readonly \\
              cp /nginx/conf /tmp/conf
            """
                .formatted("a".repeat(64)));

    assertThat(policy.unpinnedExternalRefs(dockerfile)).containsExactly("nginx:latest");
  }

  @Test
  void externalRunMountFromSplitInsideContinuedOptionMustBeDigestPinned() throws IOException {
    Path dockerfile =
        writeDockerfile(
            """
            FROM eclipse-temurin:21-jre@sha256:%s AS runtime
            RUN --mount=type=bind,\\
            from=nginx:latest,target=/nginx,readonly cp /nginx/conf /tmp/conf
            """
                .formatted("a".repeat(64)));

    assertThat(policy.unpinnedExternalRefs(dockerfile)).containsExactly("nginx:latest");
  }

  @Test
  void heredocBodyLinesDoNotCreateImageSourceReferences() throws IOException {
    Path dockerfile =
        writeDockerfile(
            """
            FROM eclipse-temurin:21-jre@sha256:%s AS runtime
            RUN <<EOF
            COPY --from=nginx:latest /etc/nginx/nginx.conf /nginx.conf
            FROM alpine:latest
            RUN --mount=type=bind,from=busybox:latest,target=/busybox true
            EOF
            """
                .formatted("a".repeat(64)));

    assertThat(policy.unpinnedExternalRefs(dockerfile)).isEmpty();
  }

  @Test
  void imageSourcesOnHeredocStartingInstructionMustBeDigestPinned() throws IOException {
    Path dockerfile =
        writeDockerfile(
            """
            FROM eclipse-temurin:21-jre@sha256:%s AS runtime
            RUN --mount=type=bind,from=nginx:latest,target=/nginx <<EOF
            true
            EOF
            """
                .formatted("a".repeat(64)));

    assertThat(policy.unpinnedExternalRefs(dockerfile)).containsExactly("nginx:latest");
  }

  @Test
  void externalCopyFromOnBacktickContinuedInstructionMustBeDigestPinned() throws IOException {
    Path dockerfile =
        writeDockerfile(
            """
            # escape=`
            FROM eclipse-temurin:21-jre@sha256:%s AS runtime
            COPY `
              --from=nginx:latest `
              /etc/nginx/nginx.conf /nginx.conf
            """
                .formatted("a".repeat(64)));

    assertThat(policy.unpinnedExternalRefs(dockerfile)).containsExactly("nginx:latest");
  }

  @Test
  void externalRunMountFromOnBacktickContinuedInstructionMustBeDigestPinned() throws IOException {
    Path dockerfile =
        writeDockerfile(
            """
            # escape=`
            FROM eclipse-temurin:21-jre@sha256:%s AS runtime
            RUN `
              --mount=type=bind,from=nginx:latest,target=/nginx,readonly `
              cp /nginx/conf /tmp/conf
            """
                .formatted("a".repeat(64)));

    assertThat(policy.unpinnedExternalRefs(dockerfile)).containsExactly("nginx:latest");
  }

  @Test
  void onbuildExternalCopyFromMustBeDigestPinned() throws IOException {
    Path dockerfile =
        writeDockerfile(
            """
            FROM eclipse-temurin:21-jre@sha256:%s AS runtime
            ONBUILD COPY --from=nginx:latest /etc/nginx/nginx.conf /nginx.conf
            """
                .formatted("a".repeat(64)));

    assertThat(policy.unpinnedExternalRefs(dockerfile)).containsExactly("nginx:latest");
  }

  @Test
  void onbuildExternalRunMountFromMustBeDigestPinned() throws IOException {
    Path dockerfile =
        writeDockerfile(
            """
            FROM eclipse-temurin:21-jre@sha256:%s AS runtime
            ONBUILD RUN --mount=type=bind,from=nginx:latest,target=/nginx,readonly true
            """
                .formatted("a".repeat(64)));

    assertThat(policy.unpinnedExternalRefs(dockerfile)).containsExactly("nginx:latest");
  }

  @Test
  void onbuildImageSourcesDoNotReuseStageNamesFromTheTriggeringImageBuild() throws IOException {
    Path dockerfile =
        writeDockerfile(
            """
            FROM eclipse-temurin:21-jre@sha256:%s AS builder
            FROM scratch
            ONBUILD COPY --from=builder /app /app
            """
                .formatted("a".repeat(64)));

    assertThat(policy.unpinnedExternalRefs(dockerfile)).containsExactly("builder");
  }

  @Test
  void escapeDirectiveAfterOrdinaryCommentDoesNotHideFollowingCopyFrom() throws IOException {
    Path dockerfile =
        writeDockerfile(
            """
            # ordinary comment
            # escape=`
            FROM eclipse-temurin:21-jre@sha256:%s AS runtime
            RUN echo placeholder `
            COPY --from=nginx:latest /etc/nginx/nginx.conf /nginx.conf
            """
                .formatted("a".repeat(64)));

    assertThat(policy.unpinnedExternalRefs(dockerfile)).containsExactly("nginx:latest");
  }

  @Test
  void priorStageNameExemptsCopyAndRunMountStageReferences() throws IOException {
    Path dockerfile =
        writeDockerfile(
            """
            FROM eclipse-temurin:21-jre@sha256:%s AS builder
            FROM scratch
            COPY --from=builder /app /app
            RUN --mount=type=bind,from=builder,target=/builder,readonly true
            """
                .formatted("a".repeat(64)));

    assertThat(policy.unpinnedExternalRefs(dockerfile)).isEmpty();
  }

  @Test
  void priorStageIndexExemptsCopyAndRunMountStageReferences() throws IOException {
    Path dockerfile =
        writeDockerfile(
            """
            FROM eclipse-temurin:21-jre@sha256:%s AS builder
            FROM scratch
            COPY --from=0 /app /app
            RUN --mount=type=bind,from=0,target=/builder,readonly true
            """
                .formatted("a".repeat(64)));

    assertThat(policy.unpinnedExternalRefs(dockerfile)).isEmpty();
  }

  @Test
  void priorStageIndexDoesNotExemptFromBaseImageReferences() throws IOException {
    Path dockerfile =
        writeDockerfile(
            """
            FROM eclipse-temurin:21-jre@sha256:%s AS builder
            FROM 0 AS runtime
            """
                .formatted("a".repeat(64)));

    assertThat(policy.unpinnedExternalRefs(dockerfile)).containsExactly("0");
  }

  private Path writeDockerfile(String content) throws IOException {
    Path dockerfile = tempDir.resolve("Dockerfile");
    Files.writeString(dockerfile, content);
    return dockerfile;
  }
}
