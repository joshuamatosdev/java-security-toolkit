package io.github.joshuamatosdev.security.supplychain.policy;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Enforces the workflow-action-pin policy over a GitHub Actions workflow file: every external
 * {@code uses:} reference must name an immutable revision — a 40-hex commit SHA for an action or
 * reusable workflow, an {@code @sha256} digest for a {@code docker://} image.
 *
 * <p>A tag or branch ({@code actions/checkout@v4}, {@code @main}) can be repointed at new content
 * by the action's owner — or by whoever compromises that owner — between two runs, so a tag-based
 * workflow executes code CI never reviewed. A commit SHA names exact content. Repository-local
 * composite actions ({@code ./.github/actions/...}) are not external inputs and are exempt.
 *
 * <p>The workflow is parsed as YAML so block and flow collections, quoted scalars, comments, and
 * reusable-workflow jobs are evaluated consistently. Only schema-defined action references are
 * inspected: job-level {@code uses} and each {@code jobs.*.steps[*].uses} value.
 *
 * <p>Why this exists: the {@code Dockerfile} and the Gradle wrapper have executable pin policies;
 * the workflows that run them are build inputs of the same trust horizon, so their pins must be a
 * testable rule too, not a review-only convention.
 */
public final class ActionPinPolicy {

  private static final ObjectMapper WORKFLOW_MAPPER =
      new ObjectMapper(
          YAMLFactory.builder()
              .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
              .build());

  private static final Pattern SHA_PINNED = Pattern.compile("^[^@\\s]+@[0-9a-f]{40}$");

  private static final Pattern DOCKER_DIGEST_PINNED =
      Pattern.compile("^docker://[^@\\s]+@sha256:[0-9a-f]{64}$");

  /** True when the action reference pins an immutable 40-hex commit SHA. */
  public boolean isShaPinned(String actionRef) {
    return actionRef != null
        && actionRef.chars().noneMatch(Character::isISOControl)
        && SHA_PINNED.matcher(actionRef).matches();
  }

  /**
   * Returns the external {@code uses:} references in the workflow that are not pinned to an
   * immutable revision. An empty result means the workflow satisfies the policy.
   */
  public List<String> unpinnedActionRefs(Path workflow) {
    JsonNode document = readWorkflow(workflow);
    JsonNode jobs = requiredObject(document, "jobs", "workflow");
    List<String> unpinned = new ArrayList<>();

    Iterator<Map.Entry<String, JsonNode>> jobFields = jobs.properties().iterator();
    while (jobFields.hasNext()) {
      Map.Entry<String, JsonNode> jobField = jobFields.next();
      String jobPath = "jobs." + jobField.getKey();
      JsonNode job = requiredObject(jobField.getValue(), null, jobPath);
      inspectUses(job.get("uses"), jobPath + ".uses", unpinned);
      inspectSteps(job.get("steps"), jobPath, unpinned);
    }
    return List.copyOf(unpinned);
  }

  private void inspectSteps(JsonNode steps, String jobPath, List<String> unpinned) {
    if (steps == null) {
      return;
    }
    if (!steps.isArray()) {
      throw new IllegalArgumentException(jobPath + ".steps must be a sequence");
    }
    for (int index = 0; index < steps.size(); index++) {
      JsonNode step = requiredObject(steps.get(index), null, jobPath + ".steps[" + index + "]");
      inspectUses(step.get("uses"), jobPath + ".steps[" + index + "].uses", unpinned);
    }
  }

  private void inspectUses(JsonNode uses, String path, List<String> unpinned) {
    if (uses == null) {
      return;
    }
    String ref;
    if (uses.isNull()) {
      ref = "";
    } else if (uses.isTextual()) {
      ref = uses.textValue();
    } else {
      throw new IllegalArgumentException(path + " must be a string");
    }
    if (!isPinnedOrLocal(ref)) {
      unpinned.add(ref);
    }
  }

  private boolean isPinnedOrLocal(String ref) {
    if (ref.isEmpty() || ref.chars().anyMatch(Character::isISOControl)) {
      return false;
    }
    // A repository-local composite action is versioned by the same commit as the workflow itself.
    if (ref.startsWith("./")) {
      return true;
    }
    if (ref.startsWith("docker://")) {
      return DOCKER_DIGEST_PINNED.matcher(ref).matches();
    }
    return isShaPinned(ref);
  }

  private static JsonNode requiredObject(JsonNode parent, String field, String path) {
    JsonNode value = field == null ? parent : parent.get(field);
    if (value == null || !value.isObject()) {
      String fieldPath = field == null ? path : path + "." + field;
      throw new IllegalArgumentException(fieldPath + " must be a mapping");
    }
    return value;
  }

  private static JsonNode readWorkflow(Path workflow) {
    try {
      JsonNode document = WORKFLOW_MAPPER.readTree(workflow.toFile());
      if (document == null || !document.isObject()) {
        throw new IllegalArgumentException("workflow must contain a YAML mapping: " + workflow);
      }
      return document;
    } catch (IOException ex) {
      throw new UncheckedIOException("failed to parse workflow at " + workflow, ex);
    }
  }
}
