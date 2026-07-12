package io.github.joshuamatosdev.security.crypto.jca;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

final class JcaKeyValidation {

    private static final ECParameterSpec P256 = namedEcParameters("secp256r1");

    private JcaKeyValidation() {}

    static boolean isEd25519Pair(final KeyPair keyPair) {
        return isEd25519(keyPair.getPrivate()) && isEd25519(keyPair.getPublic());
    }

    static boolean isEd25519PublicKey(final PublicKey publicKey) {
        return isEd25519(publicKey);
    }

    static boolean isP256Pair(final KeyPair keyPair) {
        return keyPair.getPrivate() instanceof ECPrivateKey privateKey
                && keyPair.getPublic() instanceof ECPublicKey publicKey
                && sameEcParameters(P256, privateKey.getParams())
                && sameEcParameters(P256, publicKey.getParams());
    }

    static boolean isP256PublicKey(final PublicKey publicKey) {
        return publicKey instanceof ECPublicKey ecPublicKey
                && sameEcParameters(P256, ecPublicKey.getParams());
    }

    private static boolean isEd25519(final Key key) {
        if (key == null) {
            return false;
        }
        final String algorithm = key.getAlgorithm();
        return "Ed25519".equalsIgnoreCase(algorithm) || "EdDSA".equalsIgnoreCase(algorithm);
    }

    private static ECParameterSpec namedEcParameters(final String curveName) {
        try {
            final AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(curveName));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (final GeneralSecurityException ex) {
            throw new IllegalStateException("EC parameter resolution failed for " + curveName, ex);
        }
    }

    private static boolean sameEcParameters(final ECParameterSpec expected, final ECParameterSpec actual) {
        return actual != null
                && expected.getCofactor() == actual.getCofactor()
                && expected.getOrder().equals(actual.getOrder())
                && expected.getGenerator().equals(actual.getGenerator())
                && expected.getCurve().equals(actual.getCurve());
    }
}
