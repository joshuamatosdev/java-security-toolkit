package io.github.joshuamatosdev.security.supplychain.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses a CycloneDX {@code bom.json} into the {@link SbomDocument} projection the integrity gate
 * checks. Missing fields read as {@code null} rather than throwing, so the gate — not the parser —
 * decides what a well-formed bill must contain.
 */
public final class SbomReader {

  private final ObjectMapper mapper = new ObjectMapper();

  public SbomDocument read(Path bomJson) {
    try {
      JsonNode root = mapper.readTree(Files.readString(bomJson));
      List<SbomDocument.Component> components = new ArrayList<>();
      for (JsonNode component : root.path("components")) {
        components.add(
            new SbomDocument.Component(
                text(component, "name"), text(component, "version"), text(component, "purl")));
      }
      return new SbomDocument(
          text(root, "bomFormat"), text(root, "specVersion"), text(root, "serialNumber"), components);
    } catch (IOException e) {
      throw new UncheckedIOException("failed to read SBOM at " + bomJson, e);
    }
  }

  private static String text(JsonNode node, String field) {
    return node.path(field).asText(null);
  }
}
