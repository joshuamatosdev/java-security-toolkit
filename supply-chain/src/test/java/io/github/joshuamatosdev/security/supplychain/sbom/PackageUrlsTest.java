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
}
