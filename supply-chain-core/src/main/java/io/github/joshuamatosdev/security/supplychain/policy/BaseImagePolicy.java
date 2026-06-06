package io.github.joshuamatosdev.security.supplychain.policy;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Enforces the base-image-pin policy over a Dockerfile: every <em>external</em> image source must
 * be referenced by an immutable {@code @sha256} content digest, not a mutable tag.
 *
 * <p>A tag ({@code eclipse-temurin:21-jre}) can be repointed at new content by the registry between
 * two builds, so a tag-based build is neither reproducible nor tamper-evident. A digest names exact
 * bytes. Multi-stage references — a {@code FROM <stage>}, {@code COPY --from=<stage>}, or
 * {@code RUN --mount=...,from=<stage>} that names an earlier {@code AS <stage>} — and the empty
 * {@code scratch} base are not external images and are exempt.
 *
 * <p>Why this exists: base-image policy makes container provenance a testable rule rather than a
 * checklist item.
 */
public final class BaseImagePolicy {

  private static final char DEFAULT_ESCAPE = '\\';

  private static final Pattern FROM_REF =
      Pattern.compile("^\\s*FROM\\s+(?:--platform=\\S+\\s+)?(\\S+)", Pattern.CASE_INSENSITIVE);

  private static final Pattern AS_STAGE =
      Pattern.compile("^\\s*FROM\\s+(?:--platform=\\S+\\s+)?\\S+\\s+AS\\s+(\\S+)\\s*$", Pattern.CASE_INSENSITIVE);

  private static final Pattern INSTRUCTION_WITH_ARGS =
      Pattern.compile("^\\s*([A-Z]+)\\s+(.*)$", Pattern.CASE_INSENSITIVE);

  private static final Pattern DIGEST_PINNED =
      Pattern.compile("^\\S+@sha256:[0-9a-f]{64}$");

  private static final Pattern HEREDOC_TOKEN =
      Pattern.compile("(?<!\\S)<<(-?)(?:\"([^\"]+)\"|'([^']+)'|(\\S+))");

  /** True when the reference pins an immutable {@code @sha256:<64 hex>} digest. */
  public boolean isDigestPinned(String imageRef) {
    return imageRef != null
        && imageRef.chars().noneMatch(Character::isISOControl)
        && DIGEST_PINNED.matcher(imageRef).matches();
  }

  /**
   * Returns the external image references in the Dockerfile that are not digest-pinned. An empty
   * result means the Dockerfile satisfies the policy.
   */
  public List<String> unpinnedExternalRefs(Path dockerfile) {
    List<String> unpinned = new ArrayList<>();
    Set<String> stageNames = new LinkedHashSet<>();
    int priorStageCount = 0;
    for (String instruction : logicalInstructions(readLines(dockerfile))) {
      Matcher ref = FROM_REF.matcher(instruction);
      if (ref.find()) {
        addIfUnpinnedExternal(unpinned, stageNames, priorStageCount, ref.group(1), false);
        priorStageCount++;
      }
      Matcher stage = AS_STAGE.matcher(instruction);
      if (stage.matches()) {
        stageNames.add(normalizeStageName(stage.group(1)));
      }
      for (ImageSourceRef sourceRef : imageSourceRefs(instruction)) {
        boolean allowCurrentStageReferences = sourceRef.allowCurrentStageReferences();
        Set<String> sourceStageNames = allowCurrentStageReferences ? stageNames : Set.of();
        int sourcePriorStageCount = allowCurrentStageReferences ? priorStageCount : 0;
        addIfUnpinnedExternal(
            unpinned,
            sourceStageNames,
            sourcePriorStageCount,
            sourceRef.ref(),
            allowCurrentStageReferences);
      }
    }
    return unpinned;
  }

  private void addIfUnpinnedExternal(
      List<String> unpinned,
      Set<String> stageNames,
      int priorStageCount,
      String imageRef,
      boolean allowPriorStageIndex) {
    if (isExternalImage(imageRef, stageNames, priorStageCount, allowPriorStageIndex)
        && !isDigestPinned(imageRef)) {
      unpinned.add(imageRef);
    }
  }

  private static List<ImageSourceRef> imageSourceRefs(String instruction) {
    return imageSourceRefs(instruction, true);
  }

  private static List<ImageSourceRef> imageSourceRefs(
      String instruction, boolean allowCurrentStageReferences) {
    Matcher instructionWithArgs = INSTRUCTION_WITH_ARGS.matcher(instruction);
    if (!instructionWithArgs.matches()) {
      return List.of();
    }
    String name = instructionWithArgs.group(1).toUpperCase(Locale.ROOT);
    String args = instructionWithArgs.group(2);
    if ("ONBUILD".equals(name)) {
      return imageSourceRefs(args, false);
    }
    if ("COPY".equals(name)) {
      return copyFromRefs(args, allowCurrentStageReferences);
    }
    if ("RUN".equals(name)) {
      return runMountFromRefs(args, allowCurrentStageReferences);
    }
    return List.of();
  }

  private static List<ImageSourceRef> copyFromRefs(String args, boolean allowCurrentStageReferences) {
    List<ImageSourceRef> refs = new ArrayList<>();
    for (String option : leadingOptions(args)) {
      if (option.startsWith("--from=")) {
        refs.add(
            new ImageSourceRef(option.substring("--from=".length()), allowCurrentStageReferences));
      }
    }
    return refs;
  }

  private static List<ImageSourceRef> runMountFromRefs(
      String args, boolean allowCurrentStageReferences) {
    List<ImageSourceRef> refs = new ArrayList<>();
    for (String option : leadingOptions(args)) {
      if (!option.startsWith("--mount=")) {
        continue;
      }
      String mountOptions = option.substring("--mount=".length());
      for (String field : mountOptions.split(",")) {
        if (field.startsWith("from=")) {
          refs.add(
              new ImageSourceRef(field.substring("from=".length()), allowCurrentStageReferences));
        }
      }
    }
    return refs;
  }

  private static List<String> leadingOptions(String args) {
    List<String> options = new ArrayList<>();
    int index = skipWhitespace(args, 0);
    while (args.startsWith("--", index)) {
      int start = index;
      index = nextWhitespace(args, index);
      options.add(args.substring(start, index));
      index = skipWhitespace(args, index);
    }
    return options;
  }

  private static int skipWhitespace(String value, int index) {
    int current = index;
    while (current < value.length() && Character.isWhitespace(value.charAt(current))) {
      current++;
    }
    return current;
  }

  private static int nextWhitespace(String value, int index) {
    int current = index;
    while (current < value.length() && !Character.isWhitespace(value.charAt(current))) {
      current++;
    }
    return current;
  }

  private static List<String> logicalInstructions(List<String> physicalLines) {
    List<String> instructions = new ArrayList<>();
    StringBuilder current = new StringBuilder();
    char escape = dockerfileEscape(physicalLines);
    List<HeredocMarker> pendingHeredocs = new ArrayList<>();
    for (String physicalLine : physicalLines) {
      if (!pendingHeredocs.isEmpty()) {
        if (isHeredocTerminator(physicalLine.stripTrailing(), pendingHeredocs.getFirst())) {
          pendingHeredocs.removeFirst();
        }
        continue;
      }
      if (isCommentLine(physicalLine)) {
        continue;
      }
      String line = physicalLine.stripTrailing();
      if (line.isBlank()) {
        continue;
      }
      boolean continued = line.charAt(line.length() - 1) == escape;
      String segment = continued ? line.substring(0, line.length() - 1) : line;
      appendInstructionSegment(current, segment);
      if (!continued && !current.isEmpty()) {
        String instruction = current.toString().strip();
        if (!instruction.isEmpty()) {
          instructions.add(instruction);
          pendingHeredocs.addAll(heredocMarkers(instruction));
        }
        current.setLength(0);
      }
    }
    if (!current.isEmpty()) {
      String instruction = current.toString().strip();
      if (!instruction.isEmpty()) {
        instructions.add(instruction);
      }
    }
    return instructions;
  }

  private static List<HeredocMarker> heredocMarkers(String instruction) {
    Matcher marker = HEREDOC_TOKEN.matcher(instruction);
    List<HeredocMarker> markers = new ArrayList<>();
    while (marker.find()) {
      String delimiter = heredocDelimiter(marker);
      if (!delimiter.isEmpty()) {
        markers.add(new HeredocMarker(delimiter, "-".equals(marker.group(1))));
      }
    }
    return markers;
  }

  private static String heredocDelimiter(Matcher marker) {
    if (marker.group(2) != null) {
      return marker.group(2);
    }
    if (marker.group(3) != null) {
      return marker.group(3);
    }
    return marker.group(4);
  }

  private static boolean isHeredocTerminator(String line, HeredocMarker marker) {
    String candidate = marker.allowLeadingTabs() ? stripLeadingTabs(line) : line;
    return candidate.equals(marker.delimiter());
  }

  private static String stripLeadingTabs(String value) {
    int index = 0;
    while (index < value.length() && value.charAt(index) == '\t') {
      index++;
    }
    return value.substring(index);
  }

  private static boolean isCommentLine(String line) {
    return line.stripLeading().startsWith("#");
  }

  private static char dockerfileEscape(List<String> physicalLines) {
    for (String physicalLine : physicalLines) {
      String line = physicalLine.strip();
      if (line.isEmpty()) {
        return DEFAULT_ESCAPE;
      }
      if (!line.startsWith("#")) {
        return DEFAULT_ESCAPE;
      }
      String comment = line.substring(1).strip();
      int separator = comment.indexOf('=');
      if (separator < 0) {
        return DEFAULT_ESCAPE;
      }
      String key = comment.substring(0, separator).strip();
      if ("escape".equalsIgnoreCase(key)) {
        return escapeDirectiveValue(comment.substring(separator + 1).strip());
      }
      if (isParserDirectiveKey(key)) {
        continue;
      }
      return DEFAULT_ESCAPE;
    }
    return DEFAULT_ESCAPE;
  }

  private static char escapeDirectiveValue(String value) {
    return "`".equals(value) ? '`' : DEFAULT_ESCAPE;
  }

  private static boolean isParserDirectiveKey(String key) {
    return "syntax".equalsIgnoreCase(key) || "check".equalsIgnoreCase(key);
  }

  private static void appendInstructionSegment(StringBuilder current, String segment) {
    if (segment.isBlank()) {
      return;
    }
    current.append(segment);
  }

  private static boolean isExternalImage(
      String ref, Set<String> stageNames, int priorStageCount, boolean allowPriorStageIndex) {
    String normalized = ref.toLowerCase(Locale.ROOT);
    return !"scratch".equals(normalized)
        && !stageNames.contains(normalized)
        && (!allowPriorStageIndex || !isPriorStageIndex(ref, priorStageCount));
  }

  private static String normalizeStageName(String ref) {
    return ref.toLowerCase(Locale.ROOT);
  }

  private static boolean isPriorStageIndex(String ref, int priorStageCount) {
    try {
      int stageIndex = Integer.parseInt(ref);
      return stageIndex >= 0 && stageIndex < priorStageCount;
    } catch (NumberFormatException ex) {
      return false;
    }
  }

  private record ImageSourceRef(String ref, boolean allowCurrentStageReferences) {}

  private record HeredocMarker(String delimiter, boolean allowLeadingTabs) {}

  private static List<String> readLines(Path dockerfile) {
    try {
      return Files.readAllLines(dockerfile);
    } catch (IOException e) {
      throw new UncheckedIOException("failed to read Dockerfile at " + dockerfile, e);
    }
  }
}
