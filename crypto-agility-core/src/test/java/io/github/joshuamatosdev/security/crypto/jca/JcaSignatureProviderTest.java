package io.github.joshuamatosdev.security.crypto.jca;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

import io.github.joshuamatosdev.security.crypto.api.KeyHandle;
import io.github.joshuamatosdev.security.crypto.api.SignatureAlgorithm;
import io.github.joshuamatosdev.security.crypto.api.SignatureProvider;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class JcaSignatureProviderTest {

    private static final byte[] PAYLOAD = "ledger entry 42".getBytes(StandardCharsets.UTF_8);

    @Test
    void ecdsaP256UsesJoseEs256P1363SignatureFormat() {
        final SignatureProvider provider = JcaSignatureProviders.ecdsaP256();
        final KeyHandle handle = provider.generateKey("k1");

        final byte[] signature = handle.sign(PAYLOAD);

        assertThat(signature).hasSize(64);
        assertThat(provider.verify(handle.publicKey(), PAYLOAD, signature)).isTrue();
    }

    @Test
    void ecdsaP256RejectsSignatureMadeWithAnotherEcCurve() throws GeneralSecurityException {
        final SignatureProvider provider = JcaSignatureProviders.ecdsaP256();
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        final KeyPair p384Key = generator.generateKeyPair();
        final Signature signer = Signature.getInstance("SHA256withECDSAinP1363Format");
        signer.initSign(p384Key.getPrivate());
        signer.update(PAYLOAD);

        assertThat(provider.verify(p384Key.getPublic().getEncoded(), PAYLOAD, signer.sign())).isFalse();
    }

    @Test
    void providerConfigurationMustMatchReportedAlgorithm() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaSignatureProvider(
                        SignatureAlgorithm.ECDSA_P256,
                        "EC",
                        null,
                        "SHA256withECDSAinP1363Format",
                        "EC"))
                .withMessage("ECDSA_P256 provider must be constrained to secp256r1");
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaSignatureProvider(
                        SignatureAlgorithm.ECDSA_P256,
                        "EC",
                        new ECGenParameterSpec("secp256r1"),
                        "SHA256withECDSA",
                        "EC"))
                .withMessage("ECDSA_P256 provider must use SHA256withECDSAinP1363Format");
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaSignatureProvider(
                        SignatureAlgorithm.ED25519,
                        "EC",
                        new ECGenParameterSpec("secp256r1"),
                        "SHA256withECDSAinP1363Format",
                        "EC"))
                .withMessage("ED25519 provider must use Ed25519 JCA primitives without key parameters");
    }

    @Test
    void keyHandleConstructorRejectsInvalidInputsAndMismatchedKeyPairs() throws GeneralSecurityException {
        final KeyPair ed25519 = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        final KeyPair otherEd25519 = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();

        assertThatNullPointerException()
                .isThrownBy(() -> new JcaKeyHandle(null, SignatureAlgorithm.ED25519, "Ed25519", ed25519))
                .withMessage("keyId must not be null");
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaKeyHandle(" ", SignatureAlgorithm.ED25519, "Ed25519", ed25519))
                .withMessage("keyId must not be blank");
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaKeyHandle(
                        "k1",
                        SignatureAlgorithm.ED25519,
                        "Ed25519",
                        new KeyPair(otherEd25519.getPublic(), ed25519.getPrivate())))
                .withMessage("keyPair public key must verify signatures from its private key");
    }

    @Test
    void verifyReturnsFalseForMalformedNullOrTruncatedInputs() {
        final SignatureProvider provider = JcaSignatureProviders.ecdsaP256();
        final byte[] publicKey = provider.generateKey("k1").publicKey();
        final byte[] truncated = Arrays.copyOf(publicKey, publicKey.length / 2);

        assertThat(provider.verify(new byte[] {0x30, 0x05, 0x02}, PAYLOAD, new byte[64])).isFalse();
        assertThat(provider.verify(truncated, PAYLOAD, new byte[64])).isFalse();
        assertThatCode(() -> provider.verify(null, PAYLOAD, new byte[64])).doesNotThrowAnyException();
        assertThatCode(() -> provider.verify(publicKey, null, new byte[64])).doesNotThrowAnyException();
        assertThatCode(() -> provider.verify(publicKey, PAYLOAD, null)).doesNotThrowAnyException();
    }

    @Test
    void postQuantumSlotStillRunsClassicalStandIn() {
        final SignatureProvider placeholder = JcaSignatureProviders.postQuantumPlaceholder();
        final KeyHandle handle = placeholder.generateKey("pqc-1");
        final byte[] signature = handle.sign(PAYLOAD);

        assertThat(SignatureAlgorithm.ML_DSA_44.fipsApproved()).isTrue();
        assertThat(JcaSignatureProviders.ed25519().verify(handle.publicKey(), PAYLOAD, signature)).isTrue();
    }
}
