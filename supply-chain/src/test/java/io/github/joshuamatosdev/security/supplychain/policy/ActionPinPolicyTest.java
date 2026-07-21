package io.github.joshuamatosdev.security.supplychain.policy;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Proves the workflow-action-pin policy is enforced against the repository's actual CI workflows,
 * and that the pinned-vs-mutable distinction the policy rests on is correct.
 *
 * <p>Why this is important to test: the workflows are the build inputs that run every other
 * supply-chain control; an action repointed through a mutable tag executes unreviewed code in CI,
 * so the SHA pin must be asserted continuously rather than assumed to stay in place.
 */
class ActionPinPolicyTest {

  private static final String PINNED_SHA = "a".repeat(40);

  private final ActionPinPolicy policy = new ActionPinPolicy();

  @TempDir Path tempDir;

  private static Path repositoryWorkflowsDir() {
    return Path.of(System.getProperty("workflows.dir", ".github/workflows"));
  }

  @Test
  void theRepositoryWorkflowsPinEveryActionByCommitSha() throws IOException {
    try (Stream<Path> workflows = Files.list(repositoryWorkflowsDir())) {
      List<Path> workflowFiles = workflows
          .filter(file -> {
            String name = file.getFileName().toString();
            return name.endsWith(".yml") || name.endsWith(".yaml");
          })
          .toList();

      assertThat(workflowFiles).as("the repository must have CI workflows to assert against").isNotEmpty();
      for (Path workflow : workflowFiles) {
        assertThat(policy.unpinnedActionRefs(workflow))
            .as("every uses: reference in %s must be pinned to an immutable revision", workflow)
            .isEmpty();
      }
    }
  }

  @Test
  void tagAndBranchRefsAreRejected() throws IOException {
    Path workflow = writeWorkflow(
        """
        jobs:
          build:
            steps:
              - uses: actions/checkout@v4
              - uses: actions/setup-java@main
        """);

    assertThat(policy.unpinnedActionRefs(workflow))
        .containsExactly("actions/checkout@v4", "actions/setup-java@main");
  }

  @Test
  void flowStyleStepsCannotBypassPinEnforcement() throws IOException {
    Path workflow = writeWorkflow(
        "jobs: {build: {runs-on: ubuntu-latest, steps: [{uses: actions/checkout@v4}]}}");

    assertThat(policy.unpinnedActionRefs(workflow)).containsExactly("actions/checkout@v4");
  }

  @Test
  void flowStyleReusableWorkflowsCannotBypassPinEnforcement() throws IOException {
    Path workflow = writeWorkflow(
        "jobs: {shared: {uses: acme/workflows/.github/workflows/build.yml@main}}");

    assertThat(policy.unpinnedActionRefs(workflow))
        .containsExactly("acme/workflows/.github/workflows/build.yml@main");
  }

  @Test
  void fullCommitShaRefsAreAccepted() throws IOException {
    Path workflow = writeWorkflow(
        """
        jobs:
          build:
            steps:
              - uses: actions/checkout@%s
              - uses: gradle/actions/setup-gradle@%s
        """.formatted(PINNED_SHA, "b".repeat(40)));

    assertThat(policy.unpinnedActionRefs(workflow)).isEmpty();
  }

  @Test
  void abbreviatedAndUppercaseShasAreRejected() throws IOException {
    Path workflow = writeWorkflow(
        """
        jobs:
          build:
            steps:
              - uses: actions/checkout@%s
              - uses: actions/setup-java@%s
        """.formatted("a".repeat(7), "A".repeat(40)));

    assertThat(policy.unpinnedActionRefs(workflow)).hasSize(2);
  }

  @Test
  void repositoryLocalCompositeActionsAreExempt() throws IOException {
    Path workflow = writeWorkflow(
        """
        jobs:
          build:
            steps:
              - uses: ./.github/actions/setup-toolchain
        """);

    assertThat(policy.unpinnedActionRefs(workflow)).isEmpty();
  }

  @Test
  void dockerRefsMustBeDigestPinned() throws IOException {
    Path workflow = writeWorkflow(
        """
        jobs:
          build:
            steps:
              - uses: docker://alpine:3.20
              - uses: docker://alpine@sha256:%s
        """.formatted("c".repeat(64)));

    assertThat(policy.unpinnedActionRefs(workflow)).containsExactly("docker://alpine:3.20");
  }

  @Test
  void reusableWorkflowRefsFollowTheSameRule() throws IOException {
    Path workflow = writeWorkflow(
        """
        jobs:
          call-shared:
            uses: acme/shared-workflows/.github/workflows/build.yml@v2
          call-pinned:
            uses: acme/shared-workflows/.github/workflows/build.yml@%s
        """.formatted(PINNED_SHA));

    assertThat(policy.unpinnedActionRefs(workflow))
        .containsExactly("acme/shared-workflows/.github/workflows/build.yml@v2");
  }

  @Test
  void quotedRefsAndTrailingCommentsAreHandled() throws IOException {
    Path workflow = writeWorkflow(
        """
        jobs:
          build:
            steps:
              - uses: 'actions/checkout@%s' # v4
              - uses: "actions/setup-java@v4"
              - uses: gradle/actions/setup-gradle@%s # v4
        """.formatted(PINNED_SHA, "d".repeat(40)));

    assertThat(policy.unpinnedActionRefs(workflow)).containsExactly("actions/setup-java@v4");
  }

  @Test
  void commentedOutUsesLinesAreIgnored() throws IOException {
    Path workflow = writeWorkflow(
        """
        jobs:
          build:
            steps:
              # - uses: actions/checkout@v4
              - uses: actions/checkout@%s
        """.formatted(PINNED_SHA));

    assertThat(policy.unpinnedActionRefs(workflow)).isEmpty();
  }

  @Test
  void emptyRefsAreRejected() throws IOException {
    Path workflow = writeWorkflow(
        """
        jobs:
          build:
            steps:
              - uses:
        """);

    assertThat(policy.unpinnedActionRefs(workflow)).containsExactly("");
  }

  @Test
  void shaPinnedReferencesAreRecognizedAndMutableOnesAreNot() {
    assertThat(policy.isShaPinned("actions/checkout@" + PINNED_SHA)).isTrue();
    assertThat(policy.isShaPinned("actions/checkout@v4")).isFalse();
    assertThat(policy.isShaPinned("actions/checkout@" + "A".repeat(40))).isFalse();
    assertThat(policy.isShaPinned("actions/checkout")).isFalse();
    assertThat(policy.isShaPinned(null)).isFalse();
  }

  private Path writeWorkflow(String content) throws IOException {
    Path workflow = tempDir.resolve("workflow.yml");
    Files.writeString(workflow, content);
    return workflow;
  }
}
