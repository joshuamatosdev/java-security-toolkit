package io.github.joshuamatosdev.security.crypto.jca;

import io.github.joshuamatosdev.security.crypto.api.SignatureProvider;
import io.github.joshuamatosdev.security.crypto.testkit.SignatureProviderContract;

class Ed25519ProviderContractTest implements SignatureProviderContract {
    @Override
    public SignatureProvider provider() {
        return JcaSignatureProviders.ed25519();
    }
}

class EcdsaP256ProviderContractTest implements SignatureProviderContract {
    @Override
    public SignatureProvider provider() {
        return JcaSignatureProviders.ecdsaP256();
    }
}

class PostQuantumPlaceholderProviderContractTest implements SignatureProviderContract {
    @Override
    public SignatureProvider provider() {
        return JcaSignatureProviders.postQuantumPlaceholder();
    }
}
