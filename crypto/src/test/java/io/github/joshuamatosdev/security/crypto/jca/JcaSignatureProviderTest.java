package io.github.joshuamatosdev.security.crypto.jca;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
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
import java.util.List;
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
    void customJcaSpecsArePlugAndPlayWithoutCoreEdits() {
        final SignatureAlgorithm customAlgorithm = SignatureAlgorithm.of("CUSTOM-ED25519");
        final SignatureProvider provider = new JcaSignatureProvider(new JcaSignatureSpec(
                customAlgorithm,
                "Ed25519",
                null,
                "Ed25519",
                "Ed25519",
                JcaKeyValidation::isEd25519Pair,
                JcaKeyValidation::isEd25519PublicKey));
        final var registry = new io.github.joshuamatosdev.security.crypto.api.SignatureProviderRegistry(
                List.of(provider));
        final KeyHandle key = registry.resolve(customAlgorithm).generateKey("custom-1");

        assertThat(provider.algorithm()).isEqualTo(customAlgorithm);
        assertThat(provider.verify(key.publicKey(), PAYLOAD, key.sign(PAYLOAD))).isTrue();
    }

    @Test
    void generatedKeyPolicyIsSuppliedByTheSpec() {
        final JcaSignatureSpec rejectingSpec = new JcaSignatureSpec(
                SignatureAlgorithm.of("REJECTING-ED25519"),
                "Ed25519",
                null,
                "Ed25519",
                "Ed25519",
                keyPair -> false,
                publicKey -> true);

        assertThatIllegalStateException()
                .isThrownBy(() -> new JcaSignatureProvider(rejectingSpec).generateKey("k1"))
                .withMessageContaining("REJECTING-ED25519");
    }

    @Test
    void keyHandleConstructorRejectsInvalidInputsAndMismatchedKeyPairs() throws GeneralSecurityException {
        final KeyPair ed25519 = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        final KeyPair otherEd25519 = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();

        assertThatNullPointerException()
                .isThrownBy(() -> new JcaKeyHandle(null, ed25519Spec(), ed25519))
                .withMessage("keyId must not be null");
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaKeyHandle(" ", ed25519Spec(), ed25519))
                .withMessage("keyId must not be blank");
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaKeyHandle(
                        "k1",
                        ed25519Spec(),
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

    private static JcaSignatureSpec ed25519Spec() {
        return new JcaSignatureSpec(
                SignatureAlgorithm.ED25519,
                "Ed25519",
                null,
                "Ed25519",
                "Ed25519",
                JcaKeyValidation::isEd25519Pair,
                JcaKeyValidation::isEd25519PublicKey);
    }
}
