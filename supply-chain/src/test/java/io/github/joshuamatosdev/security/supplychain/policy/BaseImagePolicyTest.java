package io.github.joshuamatosdev.security.supplychain.policy;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/**
 * Proves the base-image-pin policy is enforced against the module's actual Dockerfile, and that the
 * pinned-vs-floating distinction the policy rests on is correct.
 */
class BaseImagePolicyTest {

  private final BaseImagePolicy policy = new BaseImagePolicy();

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
  void aFloatingTagIsNotConsideredPinned() {
    assertThat(policy.isDigestPinned("eclipse-temurin:21-jre")).isFalse();
  }

  @Test
  void aDigestReferenceIsConsideredPinned() {
    assertThat(policy.isDigestPinned("eclipse-temurin:21-jre@sha256:" + "a".repeat(64))).isTrue();
  }

  @Test
  void aShortOrNonHexDigestIsNotPinned() {
    assertThat(policy.isDigestPinned("img@sha256:abc")).isFalse();
    assertThat(policy.isDigestPinned("img@sha256:" + "z".repeat(64))).isFalse();
  }
}
