package io.github.joshuamatosdev.security.supplychain.policy;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class DockerfileInstructions {

  private static final char DEFAULT_ESCAPE = '\\';
  private static final Pattern HEREDOC_TOKEN =
      Pattern.compile("(?<!\\S)<<(-?)(?:\"([^\"]+)\"|'([^']+)'|(\\S+))");

  private DockerfileInstructions() {}

  static List<String> logicalInstructions(List<String> physicalLines) {
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

  private record HeredocMarker(String delimiter, boolean allowLeadingTabs) {}
}
