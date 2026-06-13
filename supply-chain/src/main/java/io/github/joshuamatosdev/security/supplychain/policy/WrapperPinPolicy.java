package io.github.joshuamatosdev.security.supplychain.policy;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Enforces the build-tool-pin policy over a Gradle {@code gradle-wrapper.properties}: the wrapper
 * must resolve the exact Gradle distribution by an immutable {@code distributionSha256Sum} content
 * hash, over an HTTPS distribution URL, with {@code validateDistributionUrl} enabled.
 *
 * <p>The committed {@code gradle-wrapper.jar} is the first code that runs on every {@code ./gradlew}
 * invocation, ahead of every other build control; validating that JAR against Gradle's published
 * checksums is a CI concern ({@code gradle/actions/setup-gradle} with {@code validate-wrappers}).
 * This policy is the executable check that the distribution the wrapper then downloads is itself
 * pinned by content — not by a mutable host or a tag — so the pin cannot silently regress (for
 * example, a {@code gradle wrapper} regeneration that drops the checksum).
 *
 * <p>Why this exists: build-tool pinning is a testable rule rather than a checklist item.
 */
public final class WrapperPinPolicy {

  private static final Pattern LOWERCASE_SHA256 = Pattern.compile("[0-9a-f]{64}");

  /**
   * Returns the policy violations for the wrapper properties at {@code wrapperProperties}. An empty
   * result means the wrapper satisfies the build-tool-pin policy.
   */
  public List<String> violations(Path wrapperProperties) {
    LoadedProperties loaded = read(wrapperProperties);
    Properties properties = loaded.properties();
    List<String> violations = new ArrayList<>();

    if (!loaded.duplicateKeys().isEmpty()) {
      violations.add(
          "gradle-wrapper.properties must not define duplicate keys: "
              + String.join(", ", loaded.duplicateKeys()));
    }

    String distributionSha256Sum = properties.getProperty("distributionSha256Sum");
    if (distributionSha256Sum == null || !LOWERCASE_SHA256.matcher(distributionSha256Sum).matches()) {
      violations.add(
          "distributionSha256Sum must pin the Gradle distribution by a lowercase 64-hex SHA-256");
    }

    String distributionUrl = properties.getProperty("distributionUrl");
    violations.addAll(distributionUrlViolations(distributionUrl));

    if (!Boolean.parseBoolean(properties.getProperty("validateDistributionUrl"))) {
      violations.add("validateDistributionUrl must be true");
    }

    return violations;
  }

  private static List<String> distributionUrlViolations(String distributionUrl) {
    List<String> violations = new ArrayList<>();
    if (distributionUrl == null
        || !distributionUrl.equals(distributionUrl.strip())
        || distributionUrl.chars().anyMatch(Character::isISOControl)) {
      violations.add("distributionUrl must be a valid HTTPS URL");
      return violations;
    }
    try {
      URI uri = URI.create(distributionUrl);
      if (!"https".equalsIgnoreCase(uri.getScheme())
          || uri.getHost() == null
          || uri.getHost().isBlank()) {
        violations.add("distributionUrl must be a valid HTTPS URL");
      }
      if (uri.getUserInfo() != null) {
        violations.add("distributionUrl must not include user-info credentials");
      }
      return violations;
    } catch (IllegalArgumentException ex) {
      violations.add("distributionUrl must be a valid HTTPS URL");
      return violations;
    }
  }

  private static LoadedProperties read(Path wrapperProperties) {
    DuplicateTrackingProperties properties = new DuplicateTrackingProperties();
    try (InputStream in = Files.newInputStream(wrapperProperties)) {
      properties.load(in);
    } catch (IOException e) {
      throw new UncheckedIOException("failed to read wrapper properties at " + wrapperProperties, e);
    }
    return new LoadedProperties(properties, properties.duplicateKeys());
  }

  private record LoadedProperties(Properties properties, List<String> duplicateKeys) {}

  private static final class DuplicateTrackingProperties extends Properties {
    private final Set<String> duplicateKeys = new LinkedHashSet<>();

    @Override
    public synchronized Object put(Object key, Object value) {
      if (containsKey(key)) {
        duplicateKeys.add(String.valueOf(key));
      }
      return super.put(key, value);
    }

    List<String> duplicateKeys() {
      return List.copyOf(duplicateKeys);
    }
  }
}
