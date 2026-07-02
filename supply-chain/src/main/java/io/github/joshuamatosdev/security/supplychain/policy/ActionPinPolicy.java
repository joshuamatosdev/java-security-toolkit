package io.github.joshuamatosdev.security.supplychain.policy;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
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
 * <p>The scan is line-oriented over the conventional workflow layout ({@code uses:} as a plain
 * scalar on one line, optionally quoted, optionally followed by a comment) — the same layout every
 * mainstream workflow uses and the one this repository's CI is written in.
 *
 * <p>Why this exists: the {@code Dockerfile} and the Gradle wrapper have executable pin policies;
 * the workflows that run them are build inputs of the same trust horizon, so their pins must be a
 * testable rule too, not a review-only convention.
 */
public final class ActionPinPolicy {

  private static final Pattern USES_LINE =
      Pattern.compile("^\\s*(?:-\\s+)?uses:\\s*(.*?)\\s*$", Pattern.CASE_INSENSITIVE);

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
    List<String> unpinned = new ArrayList<>();
    for (String line : readLines(workflow)) {
      if (line.stripLeading().startsWith("#")) {
        continue;
      }
      Matcher uses = USES_LINE.matcher(line);
      if (!uses.matches()) {
        continue;
      }
      String ref = unquotedRef(uses.group(1));
      if (!isPinnedOrLocal(ref)) {
        unpinned.add(ref);
      }
    }
    return unpinned;
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

  /**
   * Extracts the reference from the scalar after {@code uses:}: strips one level of single or
   * double quotes, otherwise takes the first whitespace-delimited token (which also drops a
   * trailing {@code # comment}).
   */
  private static String unquotedRef(String rawValue) {
    if (rawValue.length() >= 2
        && (rawValue.charAt(0) == '\'' || rawValue.charAt(0) == '"')) {
      int closingQuote = rawValue.indexOf(rawValue.charAt(0), 1);
      if (closingQuote > 0) {
        return rawValue.substring(1, closingQuote);
      }
      return rawValue;
    }
    int firstWhitespace = 0;
    while (firstWhitespace < rawValue.length()
        && !Character.isWhitespace(rawValue.charAt(firstWhitespace))) {
      firstWhitespace++;
    }
    return rawValue.substring(0, firstWhitespace);
  }

  private static List<String> readLines(Path workflow) {
    try {
      return Files.readAllLines(workflow);
    } catch (IOException e) {
      throw new UncheckedIOException("failed to read workflow at " + workflow, e);
    }
  }
}
