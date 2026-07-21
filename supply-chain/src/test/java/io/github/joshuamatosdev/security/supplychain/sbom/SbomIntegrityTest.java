package io.github.joshuamatosdev.security.supplychain.sbom;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/**
 * Proves the build emits a CycloneDX SBOM and that the bill has integrity. The {@code test} task
 * {@code dependsOn(cyclonedxDirectBom)} and passes {@code -Dsbom.path}, so these assertions run
 * against the REAL generated {@code build/reports/bom.cdx.json} — not a checked-in fixture.
 *
 * <p>Why this is important to test: build trust checks only protect the system when generated
 * SBOMs and base-image pins are asserted continuously.
 */
class SbomIntegrityTest {

  private static Path generatedSbom() {
    String path = System.getProperty("sbom.path");
    assertThat(path)
        .as("the build wires -Dsbom.path; the test depends on cyclonedxDirectBom")
        .isNotNull();
    return Path.of(path);
  }

  @Test
  void buildEmitsACycloneDxBill() {
    Path bom = generatedSbom();
    assertThat(Files.exists(bom)).as("cyclonedxDirectBom must emit %s on build", bom).isTrue();

    SbomDocument doc = new SbomReader().read(bom);
    assertThat(doc.bomFormat()).isEqualTo("CycloneDX");
    assertThat(doc.specVersion()).isNotBlank();
  }

  @Test
  void theBillCarriesAUniqueSerialNumberAndEnumeratesComponents() {
    SbomDocument doc = new SbomReader().read(generatedSbom());

    assertThat(doc.serialNumber())
        .as("a CycloneDX bill is identified by a unique serialNumber")
        .isNotBlank();
    assertThat(doc.components())
        .as("the bill must enumerate the resolved dependency set")
        .isNotEmpty();
  }

  @Test
  void everyComponentCarriesAPackageUrlSoItCanBeReVerified() {
    SbomDocument doc = new SbomReader().read(generatedSbom());

    assertThat(doc.components())
        .allSatisfy(
            component ->
                assertThat(component.purl())
                    .as("component '%s' must carry a purl coordinate for advisory cross-check",
                        component.name())
                    .isNotBlank());
  }
}
