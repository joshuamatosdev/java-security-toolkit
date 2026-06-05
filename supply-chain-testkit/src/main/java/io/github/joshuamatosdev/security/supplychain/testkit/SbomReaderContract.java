package io.github.joshuamatosdev.security.supplychain.testkit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.supplychain.sbom.SbomReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/** Reusable contract tests for CycloneDX SBOM readers. */
public interface SbomReaderContract {

    /** Reader under test. */
    SbomReader reader();

    @Test
    default void validCycloneDxBillReadsCoreFieldsAndComponents() throws IOException {
        final Path bom = Files.createTempFile("sbom-reader-contract", ".json");
        try {
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
                          "purl": "pkg:maven/org.springframework/spring-core@6.2.0"
                        }
                      ]
                    }
                    """);

            final var document = reader().read(bom);

            assertThat(document.bomFormat()).isEqualTo("CycloneDX");
            assertThat(document.components()).singleElement().satisfies(component -> {
                assertThat(component.name()).isEqualTo("spring-core");
                assertThat(component.purl()).isEqualTo("pkg:maven/org.springframework/spring-core@6.2.0");
            });
        } finally {
            Files.deleteIfExists(bom);
        }
    }

    @Test
    default void malformedPackageUrlsFail() throws IOException {
        final Path bom = Files.createTempFile("sbom-reader-contract-malformed", ".json");
        try {
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
                          "purl": "maven/org.springframework/spring-core@6.2.0"
                        }
                      ]
                    }
                    """);

            assertThatThrownBy(() -> reader().read(bom))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("CycloneDX field purl must be a package-url value when present");
        } finally {
            Files.deleteIfExists(bom);
        }
    }
}
