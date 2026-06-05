package io.github.joshuamatosdev.security.supplychain.testkit;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.supplychain.policy.BaseImagePolicy;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/** Reusable contract tests for base-image digest-pin policy implementations. */
public interface BaseImagePolicyContract {

    /** Policy under test. */
    BaseImagePolicy policy();

    @Test
    default void digestPinnedReferencesAreAcceptedAndFloatingTagsAreRejected() {
        assertThat(policy().isDigestPinned("eclipse-temurin:21-jre@sha256:" + "a".repeat(64))).isTrue();
        assertThat(policy().isDigestPinned("eclipse-temurin:21-jre")).isFalse();
        assertThat(policy().isDigestPinned(null)).isFalse();
    }

    @Test
    default void dockerfilesWithExternalFloatingRefsFail() throws IOException {
        final Path dockerfile = Files.createTempFile("base-image-policy-contract", ".Dockerfile");
        try {
            Files.writeString(
                    dockerfile,
                    """
                    FROM eclipse-temurin:21-jre@sha256:%s AS runtime
                    COPY --from=nginx:latest /etc/nginx/nginx.conf /nginx.conf
                    """
                            .formatted("a".repeat(64)));

            assertThat(policy().unpinnedExternalRefs(dockerfile)).containsExactly("nginx:latest");
        } finally {
            Files.deleteIfExists(dockerfile);
        }
    }
}
