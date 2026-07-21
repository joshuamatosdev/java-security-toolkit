package io.github.joshuamatosdev.security.supplychain.sbom;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class PackageUrlsTest {

  @Test
  void canonicalizeNormalizesSchemeAndType() {
    assertThat(PackageUrls.canonicalize("PKG://MAVEN/com.acme/app@1.0.0"))
        .isEqualTo("pkg:maven/com.acme/app@1.0.0");
  }

  @Test
  void validPackageUrlAllowsQualifierAndSubpath() {
    assertThat(PackageUrls.isValid("pkg:maven/com.acme/app@1.0.0?type=jar#classes")).isTrue();
  }

  @Test
  void officialScopedNpmExampleIsValid() {
    assertThat(PackageUrls.isValid("pkg:npm/%40angular/animation@12.3.1")).isTrue();
  }

  @Test
  void officialEncodedRepositoryQualifierExampleIsValid() {
    assertThat(PackageUrls.isValid(
            "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1"
                + "?repository_url=repo.spring.io%2Frelease&packaging=sources"))
        .isTrue();
  }

  @Test
  void encodedSeparatorsAreValidInsideOpaqueComponents() {
    assertThat(PackageUrls.isValid(
            "pkg:generic/acme/component%2Fvariant@1.0%2Fhotfix"
                + "?download=true%3Fforce&tag=%40latest"))
        .isTrue();
  }

  @Test
  void canonicalizationPreservesValidPercentEncodedUtf8() {
    final String purl = "PKG://GENERIC/caf%C3%A9@1.0?label=%E6%9D%B1%E4%BA%AC";

    assertThat(PackageUrls.isValid(purl)).isTrue();
    assertThat(PackageUrls.canonicalize(purl))
        .isEqualTo("pkg:generic/caf%C3%A9@1.0?label=%E6%9D%B1%E4%BA%AC");
  }
}
