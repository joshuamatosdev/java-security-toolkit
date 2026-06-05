package io.github.joshuamatosdev.security.supplychain.sbom;

import io.github.joshuamatosdev.security.supplychain.testkit.SbomReaderContract;

class SbomReaderContractTest implements SbomReaderContract {

  @Override
  public SbomReader reader() {
    return new SbomReader();
  }
}
