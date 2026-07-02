package io.github.joshuamatosdev.security.crypto.testkit.fake;

import io.github.joshuamatosdev.security.crypto.api.SignatureAlgorithm;
import io.github.joshuamatosdev.security.crypto.api.SignatureProvider;
import io.github.joshuamatosdev.security.crypto.testkit.SignatureProviderContract;

class FakeSignatureProviderContractTest implements SignatureProviderContract {

    @Override
    public SignatureProvider provider() {
        return new FakeSignatureProvider(SignatureAlgorithm.ED25519);
    }
}
