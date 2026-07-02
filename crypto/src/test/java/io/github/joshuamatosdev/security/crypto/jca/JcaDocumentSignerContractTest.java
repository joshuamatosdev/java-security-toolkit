package io.github.joshuamatosdev.security.crypto.jca;

import io.github.joshuamatosdev.security.crypto.api.DocumentSigner;
import io.github.joshuamatosdev.security.crypto.api.KeyHandle;
import io.github.joshuamatosdev.security.crypto.api.SignatureAlgorithm;
import io.github.joshuamatosdev.security.crypto.api.SignatureProviderRegistry;
import io.github.joshuamatosdev.security.crypto.testkit.DocumentSignerContract;
import java.util.List;

class JcaDocumentSignerContractTest implements DocumentSignerContract {

    private final SignatureProviderRegistry registry = new SignatureProviderRegistry(
            List.of(JcaSignatureProviders.ed25519(), JcaSignatureProviders.ecdsaP256()));
    private final DocumentSigner signer = new DocumentSigner(registry);

    @Override
    public DocumentSigner signer() {
        return signer;
    }

    @Override
    public KeyHandle signingKey() {
        return registry.resolve(SignatureAlgorithm.ED25519).generateKey("contract-ed25519");
    }

    @Override
    public SignatureAlgorithm mismatchedAlgorithm() {
        return SignatureAlgorithm.ECDSA_P256;
    }
}
