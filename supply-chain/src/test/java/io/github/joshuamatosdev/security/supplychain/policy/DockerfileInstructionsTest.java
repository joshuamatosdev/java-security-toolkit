package io.github.joshuamatosdev.security.supplychain.policy;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class DockerfileInstructionsTest {

  @Test
  void logicalInstructionsJoinContinuationsAndSkipHeredocBodies() {
    assertThat(DockerfileInstructions.logicalInstructions(List.of(
            "# syntax=docker/dockerfile:1.7",
            "FROM eclipse-temurin:21-jre \\",
            "  AS runtime",
            "RUN <<EOF",
            "echo ignored",
            "EOF",
            "COPY --from=runtime /app /app")))
        .containsExactly(
            "FROM eclipse-temurin:21-jre   AS runtime",
            "RUN <<EOF",
            "COPY --from=runtime /app /app");
  }
}
