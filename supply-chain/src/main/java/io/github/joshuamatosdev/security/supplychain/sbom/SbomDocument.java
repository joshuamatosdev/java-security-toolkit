package io.github.joshuamatosdev.security.supplychain.sbom;

import java.util.List;
import org.jspecify.annotations.Nullable;

/**
 * The fields of a CycloneDX Software Bill of Materials that a supply-chain integrity gate reasons
 * about: the format marker, the spec version, the unique {@code serialNumber} that identifies this
 * exact bill, and the enumerated dependency {@link Component}s.
 *
 * <p>This is intentionally a small projection, not a full CycloneDX binding — the gate only needs to
 * confirm the document is a well-formed CycloneDX bill that enumerates every dependency with a
 * resolvable coordinate.
 *
 * @param bomFormat must be {@code "CycloneDX"} for a genuine bill
 * @param specVersion the CycloneDX schema version the bill was written against
 * @param serialNumber the unique identifier of this bill (a {@code urn:uuid:...})
 * @param components the enumerated dependency set
 *
 * <p>Why this exists: SBOM parsing turns generated build evidence into assertions so dependency
 * inventory drift breaks tests instead of reviews.
 */
public record SbomDocument(
    @Nullable String bomFormat,
    @Nullable String specVersion,
    @Nullable String serialNumber,
    List<Component> components) {

  public SbomDocument {
    components = components == null ? List.of() : List.copyOf(components);
  }

  /**
   * One dependency entry. The {@code purl} (package URL, e.g. {@code pkg:maven/group/name@version})
   * is the coordinate that lets a consumer resolve and re-verify the exact artifact; an SBOM whose
   * components lack purls cannot be cross-checked against an advisory feed.
   *
   * @param name the component name
   * @param version the resolved version
   * @param purl the package-URL coordinate
   */
  public record Component(
      @Nullable String name, @Nullable String version, @Nullable String purl) {}
}
