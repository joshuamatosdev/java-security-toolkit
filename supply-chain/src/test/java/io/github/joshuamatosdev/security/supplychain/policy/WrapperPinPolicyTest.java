package io.github.joshuamatosdev.security.supplychain.policy;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Proves the build-tool-pin policy is enforced against the repository's actual
 * {@code gradle-wrapper.properties}, and that the pinned-vs-floating distinction the policy rests on
 * is correct.
 *
 * <p>Why this is important to test: build trust checks only protect the system when the wrapper pin
 * is asserted continuously rather than assumed to stay in place.
 */
class WrapperPinPolicyTest {

  private final WrapperPinPolicy policy = new WrapperPinPolicy();

  @TempDir Path tempDir;

  private static Path repositoryWrapperProperties() {
    return Path.of(
        System.getProperty("wrapper.properties.path", "gradle/wrapper/gradle-wrapper.properties"));
  }

  @Test
  void theRepositoryWrapperPinsTheDistributionByContentHash() {
    assertThat(policy.violations(repositoryWrapperProperties()))
        .as("gradle-wrapper.properties must pin distributionSha256Sum over HTTPS with validateDistributionUrl")
        .isEmpty();
  }

  @Test
  void aWrapperWithoutADistributionShaIsRejected() throws IOException {
    Path wrapper =
        writeWrapper(
            """
            distributionUrl=https://services.gradle.org/distributions/gradle-9.5.1-bin.zip
            validateDistributionUrl=true
            """);

    assertThat(policy.violations(wrapper))
        .anyMatch(violation -> violation.contains("distributionSha256Sum"));
  }

  @Test
  void aNonHexDistributionShaIsRejected() throws IOException {
    Path wrapper =
        writeWrapper(
            """
            distributionSha256Sum=not-a-real-sha
            distributionUrl=https://services.gradle.org/distributions/gradle-9.5.1-bin.zip
            validateDistributionUrl=true
            """);

    assertThat(policy.violations(wrapper))
        .anyMatch(violation -> violation.contains("distributionSha256Sum"));
  }

  @Test
  void anUppercaseDistributionShaIsRejected() throws IOException {
    Path wrapper =
        writeWrapper(
            """
            distributionSha256Sum=%s
            distributionUrl=https://services.gradle.org/distributions/gradle-9.5.1-bin.zip
            validateDistributionUrl=true
            """
                .formatted("A".repeat(64)));

    assertThat(policy.violations(wrapper))
        .anyMatch(violation -> violation.contains("distributionSha256Sum"));
  }

  @Test
  void anHttpDistributionUrlIsRejected() throws IOException {
    Path wrapper =
        writeWrapper(
            """
            distributionSha256Sum=%s
            distributionUrl=http://services.gradle.org/distributions/gradle-9.5.1-bin.zip
            validateDistributionUrl=true
            """
                .formatted("a".repeat(64)));

    assertThat(policy.violations(wrapper)).anyMatch(violation -> violation.contains("HTTPS"));
  }

  @Test
  void aMalformedHttpsDistributionUrlIsRejected() throws IOException {
    Path wrapper =
        writeWrapper(
            """
            distributionSha256Sum=%s
            distributionUrl=https://
            validateDistributionUrl=true
            """
                .formatted("a".repeat(64)));

    assertThat(policy.violations(wrapper)).anyMatch(violation -> violation.contains("valid HTTPS URL"));
  }

  @Test
  void duplicateWrapperKeysAreRejected() throws IOException {
    Path wrapper =
        writeWrapper(
            """
            distributionSha256Sum=%s
            distributionUrl=https://services.gradle.org/distributions/gradle-9.5.1-bin.zip
            distributionUrl=https://downloads.gradle.org/distributions/gradle-9.5.1-bin.zip
            validateDistributionUrl=true
            """
                .formatted("a".repeat(64)));

    assertThat(policy.violations(wrapper))
        .anyMatch(violation -> violation.contains("duplicate keys: distributionUrl"));
  }

  @Test
  void distributionUrlWithUserInfoIsRejected() throws IOException {
    Path wrapper =
        writeWrapper(
            """
            distributionSha256Sum=%s
            distributionUrl=https://wrapper-userinfo@services.gradle.org/distributions/gradle-9.5.1-bin.zip
            validateDistributionUrl=true
            """
                .formatted("a".repeat(64)));

    assertThat(policy.violations(wrapper))
        .anyMatch(violation -> violation.contains("must not include user-info"));
  }

  @Test
  void disabledUrlValidationIsRejected() throws IOException {
    Path wrapper =
        writeWrapper(
            """
            distributionSha256Sum=%s
            distributionUrl=https://services.gradle.org/distributions/gradle-9.5.1-bin.zip
            validateDistributionUrl=false
            """
                .formatted("a".repeat(64)));

    assertThat(policy.violations(wrapper))
        .anyMatch(violation -> violation.contains("validateDistributionUrl"));
  }

  @Test
  void aFullyPinnedWrapperHasNoViolations() throws IOException {
    Path wrapper =
        writeWrapper(
            """
            distributionSha256Sum=%s
            distributionUrl=https://services.gradle.org/distributions/gradle-9.5.1-bin.zip
            validateDistributionUrl=true
            """
                .formatted("a".repeat(64)));

    assertThat(policy.violations(wrapper)).isEmpty();
  }

  private Path writeWrapper(String content) throws IOException {
    Path wrapper = tempDir.resolve("gradle-wrapper.properties");
    Files.writeString(wrapper, content);
    return wrapper;
  }
}
