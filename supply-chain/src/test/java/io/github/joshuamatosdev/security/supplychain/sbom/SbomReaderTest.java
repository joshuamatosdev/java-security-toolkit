package io.github.joshuamatosdev.security.supplychain.sbom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.core.JsonParseException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Sbom Reader test coverage.
 *
 * <p>Why this is important to test: build trust checks only protect the system when generated SBOMs
 * and base-image pins are asserted continuously.
 */
class SbomReaderTest {

  @TempDir Path tempDir;

  @Test
  void rejectsCycloneDxDocumentWhenTheRootIsNotAnObject() throws Exception {
    Path bom = tempDir.resolve("bom.json");
    Files.writeString(
        bom,
        """
        [
          {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6"
          }
        ]
        """);

    assertThatThrownBy(() -> new SbomReader().read(bom))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("CycloneDX SBOM root must be an object");
  }

  @Test
  void rejectsCycloneDxComponentsWhenTheyAreNotAnArray() throws Exception {
    Path bom = tempDir.resolve("bom.json");
    Files.writeString(
        bom,
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
          "components": {
            "spring-core": {
              "name": "spring-core",
              "version": "6.2.0",
              "purl": "pkg:maven/org.springframework/spring-core@6.2.0"
            }
          }
        }
        """);

    assertThatThrownBy(() -> new SbomReader().read(bom))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("CycloneDX components must be an array");
  }

  @Test
  void rejectsCycloneDxComponentEntriesWhenTheyAreNotObjects() throws Exception {
    Path bom = tempDir.resolve("bom.json");
    Files.writeString(
        bom,
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
          "components": [
            "pkg:maven/org.springframework/spring-core@6.2.0"
          ]
        }
        """);

    assertThatThrownBy(() -> new SbomReader().read(bom))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("CycloneDX component entries must be objects");
  }

  @Test
  void rejectsCycloneDxTopLevelFieldsWhenTheyAreNotText() throws Exception {
    Path bom = tempDir.resolve("bom.json");
    Files.writeString(
        bom,
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": { "value": "1.6" },
          "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
          "components": []
        }
        """);

    assertThatThrownBy(() -> new SbomReader().read(bom))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("CycloneDX field specVersion must be text when present");
  }

  @Test
  void rejectsCycloneDxComponentFieldsWhenTheyAreNotText() throws Exception {
    Path bom = tempDir.resolve("bom.json");
    Files.writeString(
        bom,
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
          "components": [
            {
              "name": "spring-core",
              "version": "6.2.0",
              "purl": { "coordinate": "pkg:maven/org.springframework/spring-core@6.2.0" }
            }
          ]
        }
        """);

    assertThatThrownBy(() -> new SbomReader().read(bom))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("CycloneDX field purl must be text when present");
  }

  @Test
  void rejectsCycloneDxTextFieldsWithLeadingOrTrailingWhitespace() throws Exception {
    Path bom = tempDir.resolve("bom.json");
    Files.writeString(
        bom,
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6 ",
          "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
          "components": []
        }
        """);

    assertThatThrownBy(() -> new SbomReader().read(bom))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("CycloneDX field specVersion must not include leading or trailing whitespace");
  }

  @Test
  void rejectsCycloneDxTextFieldsWithControlCharacters() throws Exception {
    Path bom = tempDir.resolve("bom.json");
    Files.writeString(
        bom,
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
          "components": [
            {
              "name": "spring-core\\nforged",
              "version": "6.2.0",
              "purl": "pkg:maven/org.springframework/spring-core@6.2.0"
            }
          ]
        }
        """);

    assertThatThrownBy(() -> new SbomReader().read(bom))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("CycloneDX field name must not contain control characters");
  }

  @Test
  void rejectsCycloneDxComponentPurlWithLeadingOrTrailingWhitespace() throws Exception {
    Path bom = tempDir.resolve("bom.json");
    Files.writeString(
        bom,
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
          "components": [
            {
              "name": "spring-core",
              "version": "6.2.0",
              "purl": " pkg:maven/org.springframework/spring-core@6.2.0"
            }
          ]
        }
        """);

    assertThatThrownBy(() -> new SbomReader().read(bom))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("CycloneDX field purl must not include leading or trailing whitespace");
  }

  @Test
  void rejectsCycloneDxSerialNumberWhenItIsNotAUuidUrn() throws Exception {
    for (String malformedSerialNumber : List.of("not-a-uuid-urn", "urn:uuid:1-1-1-1-1")) {
      Path bom = tempDir.resolve("bom.json");
      Files.writeString(
          bom,
          """
          {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "%s",
            "components": []
          }
          """
              .formatted(malformedSerialNumber));

      assertThatThrownBy(() -> new SbomReader().read(bom))
          .as("serialNumber %s", malformedSerialNumber)
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("CycloneDX field serialNumber must be a urn:uuid value when present");
    }
  }

  @Test
  void rejectsCycloneDxComponentPurlWhenItIsNotAPackageUrl() throws Exception {
    for (String malformedPurl :
        List.of(
            "maven/org.springframework/spring-core@6.2.0",
            "pkg:",
            "pkg:maven",
            "pkg:maven/",
            "pkg:mav+en/org.springframework/spring-core@6.2.0",
            "pkg:maven/org.springframework/spring-core@",
            "pkg:maven/org.springframework/@6.2.0",
            "pkg:maven/org.springframework/spring-core@@6.2.0",
            "pkg:maven/org.springframework/spring@core@6.2.0",
            "pkg:maven/org@springframework/spring-core",
            "pkg:maven/org.springframework/spring-core@6.2.0/sources",
            "pkg:maven/org.springframework/spring-core@6.2.0?download",
            "pkg:maven/org.springframework/spring-core@6.2.0?type=",
            "pkg:maven/org.springframework/spring-core@6.2.0?Type=jar",
            "pkg:maven/org.springframework/spring-core@6.2.0?type=jar&type=sources",
            "pkg:maven/org.springframework/spring-core@6.2.0?type=jar?download=true",
            "pkg:maven/org.springframework/spring-core@6.2.0?type=jar=source",
            "pkg:maven/org.springframework/spring-core@6.2.0?repository_url=https://repo.maven.apache.org/maven2",
            "pkg:maven/org.springframework/spring-core@6.2.0?tag=@latest",
            "pkg:maven/org.springframework/spring-core@6.2.0#.",
            "pkg:maven/org.springframework/spring-core@6.2.0#../target",
            "pkg:maven/org.springframework/spring-core@6.2.0#%2e",
            "pkg:maven/org.springframework/spring-core@6.2.0#source/%2e%2e/target",
            "pkg:maven/org%2fspringframework/spring-core@6.2.0",
            "pkg:maven/org.springframework/spring-core@6.2.0#source%2ftarget",
            "pkg:maven/org.springframework/spring-core@6.2.0#source#target",
            "pkg:maven/org.springframework/spring=core@6.2.0",
            "pkg:maven/org.springframework/spring&core@6.2.0",
            "pkg:maven/org.springframework/spring-core%C3%28@6.2.0",
            "pkg:maven/org.springframework/spring-core%0Aforged@6.2.0",
            "pkg:maven/org.springframework/spring-cöré@6.2.0",
            "pkg:maven/org.springframework/spring-core%ZZ@6.2.0",
            "pkg:maven/org.springframework/spring-core@6.2.0?type=jär",
            "pkg:maven/org.springframework/spring-core@6.2.0?type=jar%ZZ",
            "pkg:maven/org.springframework/spring-core@6.2.0#source%ZZ")) {
      Path bom = tempDir.resolve("bom.json");
      Files.writeString(
          bom,
          """
          {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
            "components": [
              {
                "name": "spring-core",
                "version": "6.2.0",
                "purl": "%s"
              }
            ]
          }
          """
              .formatted(malformedPurl));

      assertThatThrownBy(() -> new SbomReader().read(bom))
          .as("purl %s", malformedPurl)
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("CycloneDX field purl must be a package-url value when present");
    }
  }

  @Test
  void normalizesPackageUrlWithMoreThanTwoSchemeSlashes() throws Exception {
    Path bom = tempDir.resolve("bom.json");
    Files.writeString(
        bom,
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
          "components": [
            {
              "name": "spring-core",
              "version": "6.2.0",
              "purl": "pkg:////maven/org.springframework/spring-core@6.2.0"
            }
          ]
        }
        """);

    SbomDocument doc = new SbomReader().read(bom);

    assertThat(doc.components())
        .singleElement()
        .extracting(SbomDocument.Component::purl)
        .isEqualTo("pkg:maven/org.springframework/spring-core@6.2.0");
  }

  @Test
  void normalizesAcceptedPackageUrlSchemeSlashesAndTypeCase() throws Exception {
    for (String acceptedPurl :
        List.of(
            "pkg:/maven/org.springframework/spring-core@6.2.0",
            "pkg://maven/org.springframework/spring-core@6.2.0",
            "pkg:Maven/org.springframework/spring-core@6.2.0",
            "PKG:maven/org.springframework/spring-core@6.2.0",
            "Pkg://Maven/org.springframework/spring-core@6.2.0")) {
      Path bom = tempDir.resolve("bom.json");
      Files.writeString(
          bom,
          """
          {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
            "components": [
              {
                "name": "spring-core",
                "version": "6.2.0",
                "purl": "%s"
              }
            ]
          }
          """
              .formatted(acceptedPurl));

      SbomDocument doc = new SbomReader().read(bom);

      assertThat(doc.components())
          .singleElement()
          .extracting(SbomDocument.Component::purl)
          .isEqualTo("pkg:maven/org.springframework/spring-core@6.2.0");
    }
  }

  @Test
  void preservesValidPercentEncodedUtf8InAcceptedPackageUrls() throws Exception {
    Path bom = tempDir.resolve("bom.json");
    Files.writeString(
        bom,
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
          "components": [
            {
              "name": "café",
              "version": "1.0",
              "purl": "PKG://GENERIC/caf%C3%A9@1.0?label=%E6%9D%B1%E4%BA%AC"
            }
          ]
        }
        """);

    SbomDocument doc = new SbomReader().read(bom);

    assertThat(doc.components())
        .singleElement()
        .extracting(SbomDocument.Component::purl)
        .isEqualTo("pkg:generic/caf%C3%A9@1.0?label=%E6%9D%B1%E4%BA%AC");
  }

  @Test
  void rejectsDuplicateJsonKeysInsteadOfLettingTheLastValueWin() throws Exception {
    Path bom = tempDir.resolve("bom.json");
    Files.writeString(
        bom,
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
          "components": [
            {
              "name": "spring-core",
              "name": "shadowed-name",
              "version": "6.2.0",
              "purl": "pkg:maven/org.springframework/spring-core@6.2.0"
            }
          ]
        }
        """);

    assertThatThrownBy(() -> new SbomReader().read(bom))
        .isInstanceOf(UncheckedIOException.class)
        .hasMessageContaining("failed to read SBOM")
        .hasRootCauseInstanceOf(JsonParseException.class)
        .hasStackTraceContaining("Duplicate field 'name'");
  }

  @Test
  void rejectsTrailingJsonTokensAfterTheCycloneDxDocument() throws Exception {
    Path bom = tempDir.resolve("bom.json");
    Files.writeString(
        bom,
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
          "components": []
        }
        {
          "bomFormat": "Shadowed"
        }
        """);

    assertThatThrownBy(() -> new SbomReader().read(bom))
        .isInstanceOf(UncheckedIOException.class)
        .hasMessageContaining("failed to read SBOM")
        .hasRootCauseInstanceOf(com.fasterxml.jackson.core.JsonProcessingException.class);
  }
}
