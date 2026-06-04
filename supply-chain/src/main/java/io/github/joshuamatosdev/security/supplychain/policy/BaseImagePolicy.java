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
 * Enforces the base-image-pin policy over a Dockerfile: every <em>external</em> base image must be
 * referenced by an immutable {@code @sha256} content digest, not a mutable tag.
 *
 * <p>A tag ({@code eclipse-temurin:21-jre}) can be repointed at new content by the registry between
 * two builds, so a tag-based build is neither reproducible nor tamper-evident. A digest names exact
 * bytes. Multi-stage references — a {@code FROM <stage>} that names an earlier {@code AS <stage>} —
 * and the empty {@code scratch} base are not external images and are exempt.
 */
public final class BaseImagePolicy {

  private static final Pattern FROM_REF =
      Pattern.compile("^\\s*FROM\\s+(?:--platform=\\S+\\s+)?(\\S+)", Pattern.CASE_INSENSITIVE);

  private static final Pattern AS_STAGE =
      Pattern.compile("\\bAS\\s+(\\S+)\\s*$", Pattern.CASE_INSENSITIVE);

  private static final Pattern DIGEST_PINNED = Pattern.compile("@sha256:[0-9a-f]{64}$");

  /** True when the reference pins an immutable {@code @sha256:<64 hex>} digest. */
  public boolean isDigestPinned(String imageRef) {
    return DIGEST_PINNED.matcher(imageRef.trim()).find();
  }

  /**
   * Returns the external base-image references in the Dockerfile that are not digest-pinned. An
   * empty result means the Dockerfile satisfies the policy.
   */
  public List<String> unpinnedExternalRefs(Path dockerfile) {
    List<String> refs = new ArrayList<>();
    Set<String> stageNames = new LinkedHashSet<>();
    for (String line : readLines(dockerfile)) {
      Matcher ref = FROM_REF.matcher(line);
      if (!ref.find()) {
        continue;
      }
      refs.add(ref.group(1));
      Matcher stage = AS_STAGE.matcher(line);
      if (stage.find()) {
        stageNames.add(stage.group(1).toLowerCase(Locale.ROOT));
      }
    }
    return refs.stream()
        .filter(ref -> isExternalImage(ref, stageNames))
        .filter(ref -> !isDigestPinned(ref))
        .toList();
  }

  private static boolean isExternalImage(String ref, Set<String> stageNames) {
    String normalized = ref.toLowerCase(Locale.ROOT);
    return !"scratch".equals(normalized) && !stageNames.contains(normalized);
  }

  private static List<String> readLines(Path dockerfile) {
    try {
      return Files.readAllLines(dockerfile);
    } catch (IOException e) {
      throw new UncheckedIOException("failed to read Dockerfile at " + dockerfile, e);
    }
  }
}
