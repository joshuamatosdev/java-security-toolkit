package io.github.joshuamatosdev.security.supplychain.testkit;

import io.github.joshuamatosdev.security.supplychain.sbom.SbomReader;

class SbomReaderContractTest implements SbomReaderContract {

    @Override
    public SbomReader reader() {
        return new SbomReader();
    }
}
