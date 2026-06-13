package io.github.joshuamatosdev.security.supplychain.sbom;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Parses a CycloneDX {@code bom.json} into the {@link SbomDocument} projection the integrity gate
 * checks. Missing fields read as {@code null} rather than throwing, so the gate — not the parser —
 * decides what a well-formed bill must contain.
 *
 * <p>Why this exists: SBOM parsing turns generated build evidence into assertions so dependency
 * inventory drift breaks tests instead of reviews.
 */
public final class SbomReader {

  private static final Pattern SERIAL_NUMBER_UUID =
      Pattern.compile(
          "urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
          Pattern.CASE_INSENSITIVE);

  private final ObjectMapper mapper =
      JsonMapper.builder()
          .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
          .enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY)
          .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
          .build();

  public SbomDocument read(Path bomJson) {
    try {
      JsonNode root = mapper.readTree(Files.readString(bomJson));
      if (!root.isObject()) {
        throw new IllegalArgumentException("CycloneDX SBOM root must be an object");
      }
      List<SbomDocument.Component> components = new ArrayList<>();
      JsonNode componentNodes = root.path("components");
      if (!componentNodes.isMissingNode() && !componentNodes.isArray()) {
        throw new IllegalArgumentException("CycloneDX components must be an array");
      }
      for (JsonNode component : componentNodes) {
        if (!component.isObject()) {
          throw new IllegalArgumentException("CycloneDX component entries must be objects");
        }
        components.add(
            new SbomDocument.Component(
                text(component, "name"), text(component, "version"), purl(component)));
      }
      return new SbomDocument(
          text(root, "bomFormat"), text(root, "specVersion"), serialNumber(root), components);
    } catch (IOException e) {
      throw new UncheckedIOException("failed to read SBOM at " + bomJson, e);
    }
  }

  private static String text(JsonNode node, String field) {
    JsonNode value = node.get(field);
    if (value == null || value.isNull()) {
      return null;
    }
    if (!value.isTextual()) {
      throw new IllegalArgumentException("CycloneDX field " + field + " must be text when present");
    }
    String text = value.asText();
    if (!text.equals(text.strip())) {
      throw new IllegalArgumentException(
          "CycloneDX field " + field + " must not include leading or trailing whitespace");
    }
    if (text.chars().anyMatch(Character::isISOControl)) {
      throw new IllegalArgumentException(
          "CycloneDX field " + field + " must not contain control characters");
    }
    return text;
  }

  private static String serialNumber(JsonNode node) {
    String serialNumber = text(node, "serialNumber");
    if (serialNumber == null) {
      return null;
    }
    if (!SERIAL_NUMBER_UUID.matcher(serialNumber).matches()) {
      throw new IllegalArgumentException(
          "CycloneDX field serialNumber must be a urn:uuid value when present");
    }
    try {
      UUID.fromString(serialNumber.substring("urn:uuid:".length()));
    } catch (IllegalArgumentException ex) {
      throw new IllegalArgumentException(
          "CycloneDX field serialNumber must be a urn:uuid value when present", ex);
    }
    return serialNumber;
  }

  private static String purl(JsonNode node) {
    String rawPurl = text(node, "purl");
    if (rawPurl == null) {
      return null;
    }
    String purl = PackageUrls.canonicalize(rawPurl);
    if (!PackageUrls.isValid(purl)) {
      throw new IllegalArgumentException(
          "CycloneDX field purl must be a package-url value when present");
    }
    return purl;
  }
}
