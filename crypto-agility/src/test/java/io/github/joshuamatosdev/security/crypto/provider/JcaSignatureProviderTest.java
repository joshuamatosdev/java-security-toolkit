package io.github.joshuamatosdev.security.crypto.provider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

import io.github.joshuamatosdev.security.crypto.key.JcaKeyHandle;
import io.github.joshuamatosdev.security.crypto.key.KeyHandle;
import io.github.joshuamatosdev.security.crypto.registry.SignatureAlgorithm;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Jca Signature Provider test coverage.
 *
 * <p>Why this is important to test: algorithm migration depends on identical signing semantics
 * across providers and robust rejection of invalid key or signature material.
 */
class JcaSignatureProviderTest {

    private static final byte[] PAYLOAD = "ledger entry 42".getBytes(StandardCharsets.UTF_8);

    static Stream<Arguments> providers() {
        return Stream.of(
                Arguments.of(SignatureProviders.ed25519()),
                Arguments.of(SignatureProviders.ecdsaP256()),
                Arguments.of(SignatureProviders.postQuantumPlaceholder()));
    }

    @ParameterizedTest
    @MethodSource("providers")
    void generatedHandleReportsProviderAlgorithmAndKeyId(final SignatureProvider provider) {
        final KeyHandle handle = provider.generateKey("k1");

        assertThat(handle.keyId()).isEqualTo("k1");
        assertThat(handle.algorithm()).isEqualTo(provider.algorithm());
        assertThat(handle.publicKey()).isNotEmpty();
    }

    @ParameterizedTest
    @MethodSource("providers")
    void signThenVerifyRoundTrips(final SignatureProvider provider) {
        final KeyHandle handle = provider.generateKey("k1");

        final byte[] signature = handle.sign(PAYLOAD);

        assertThat(provider.verify(handle.publicKey(), PAYLOAD, signature)).isTrue();
    }

    @Test
    void ecdsaP256UsesJoseEs256P1363SignatureFormat() {
        final SignatureProvider provider = SignatureProviders.ecdsaP256();
        final KeyHandle handle = provider.generateKey("k1");

        final byte[] signature = handle.sign(PAYLOAD);

        assertThat(signature).hasSize(64);
        assertThat(provider.verify(handle.publicKey(), PAYLOAD, signature)).isTrue();
    }

    @Test
    void ecdsaP256RejectsSignatureMadeWithAnotherEcCurve() throws GeneralSecurityException {
        final SignatureProvider provider = SignatureProviders.ecdsaP256();
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        final KeyPair p384Key = generator.generateKeyPair();
        final Signature signer = Signature.getInstance("SHA256withECDSAinP1363Format");
        signer.initSign(p384Key.getPrivate());
        signer.update(PAYLOAD);

        final byte[] p384Signature = signer.sign();

        assertThat(p384Signature).hasSize(96);
        assertThat(provider.verify(p384Key.getPublic().getEncoded(), PAYLOAD, p384Signature))
                .as("ES256 is P-256; another EC curve must not verify under the P-256 provider")
                .isFalse();
    }

    @Test
    void ecdsaP256ProviderConfigurationMustConstrainEcParameters() {
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
                        new ECGenParameterSpec("secp384r1"),
                        "SHA256withECDSAinP1363Format",
                        "EC"))
                .withMessage("ECDSA_P256 provider must be constrained to secp256r1");
    }

    @Test
    void ecdsaP256ProviderConfigurationMustUseJoseP1363SignatureFormat() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaSignatureProvider(
                        SignatureAlgorithm.ECDSA_P256,
                        "EC",
                        new ECGenParameterSpec("secp256r1"),
                        "SHA256withECDSA",
                        "EC"))
                .withMessage("ECDSA_P256 provider must use SHA256withECDSAinP1363Format");
    }

    @Test
    void ed25519ProviderConfigurationMustUseEd25519Primitive() {
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
    void mlDsa44PlaceholderConfigurationMustUseTheDocumentedEd25519Primitive() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaSignatureProvider(
                        SignatureAlgorithm.ML_DSA_44,
                        "EC",
                        new ECGenParameterSpec("secp256r1"),
                        "SHA256withECDSAinP1363Format",
                        "EC"))
                .withMessage(
                        "ML_DSA_44 placeholder provider must use Ed25519 JCA primitives without key parameters");
    }

    @ParameterizedTest
    @MethodSource("providers")
    void verifyRejectsTamperedPayload(final SignatureProvider provider) {
        final KeyHandle handle = provider.generateKey("k1");
        final byte[] signature = handle.sign(PAYLOAD);

        final byte[] tampered = "ledger entry 43".getBytes(StandardCharsets.UTF_8);

        assertThat(provider.verify(handle.publicKey(), tampered, signature)).isFalse();
    }

    @ParameterizedTest
    @MethodSource("providers")
    void verifyRejectsTamperedSignature(final SignatureProvider provider) {
        final KeyHandle handle = provider.generateKey("k1");
        final byte[] signature = handle.sign(PAYLOAD);
        signature[signature.length - 1] ^= 0x01;

        assertThat(provider.verify(handle.publicKey(), PAYLOAD, signature)).isFalse();
    }

    @ParameterizedTest
    @MethodSource("providers")
    void verifyRejectsSignatureFromAnotherKey(final SignatureProvider provider) {
        final KeyHandle signingKey = provider.generateKey("k1");
        final KeyHandle otherKey = provider.generateKey("k2");
        final byte[] signature = signingKey.sign(PAYLOAD);

        assertThat(provider.verify(otherKey.publicKey(), PAYLOAD, signature)).isFalse();
    }

    @ParameterizedTest
    @MethodSource("providers")
    void generateKeyRejectsBlankKeyId(final SignatureProvider provider) {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> provider.generateKey(" "))
                .withMessage("keyId must not be blank");
    }

    @ParameterizedTest
    @MethodSource("providers")
    void generateKeyRejectsEdgePaddedKeyId(final SignatureProvider provider) {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> provider.generateKey(" k1"))
                .withMessage("keyId must not contain leading or trailing whitespace");
    }

    @ParameterizedTest
    @MethodSource("providers")
    void generateKeyRejectsControlCharactersInKeyId(final SignatureProvider provider) {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> provider.generateKey("k1\nforged"))
                .withMessage("keyId must not contain control characters");
    }

    @Test
    void keyHandleConstructorRejectsNullInputs() throws GeneralSecurityException {
        final KeyPair keyPair = ed25519KeyPair();

        assertThatNullPointerException()
                .isThrownBy(() -> new JcaKeyHandle(null, SignatureAlgorithm.ED25519, "Ed25519", keyPair))
                .withMessage("keyId must not be null");
        assertThatNullPointerException()
                .isThrownBy(() -> new JcaKeyHandle("k1", null, "Ed25519", keyPair))
                .withMessage("algorithm must not be null");
        assertThatNullPointerException()
                .isThrownBy(() -> new JcaKeyHandle("k1", SignatureAlgorithm.ED25519, null, keyPair))
                .withMessage("jcaSignatureName must not be null");
        assertThatNullPointerException()
                .isThrownBy(() -> new JcaKeyHandle("k1", SignatureAlgorithm.ED25519, "Ed25519", null))
                .withMessage("keyPair must not be null");
    }

    @Test
    void keyHandleConstructorRejectsKeyPairWithMismatchedPublicAndPrivateKeys()
            throws GeneralSecurityException {
        final KeyPair privateKeyPair = ed25519KeyPair();
        final KeyPair publicKeyPair = ed25519KeyPair();
        final KeyPair mismatchedKeyPair =
                new KeyPair(publicKeyPair.getPublic(), privateKeyPair.getPrivate());

        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaKeyHandle(
                        "k1", SignatureAlgorithm.ED25519, "Ed25519", mismatchedKeyPair))
                .withMessage("keyPair public key must verify signatures from its private key");
    }

    @Test
    void keyHandleConstructorRejectsSignaturePrimitiveThatDoesNotMatchReportedAlgorithm()
            throws GeneralSecurityException {
        final KeyPair ed25519KeyPair = ed25519KeyPair();
        final KeyPair ecdsaP256KeyPair = ecdsaP256KeyPair();

        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaKeyHandle(
                        "k1", SignatureAlgorithm.ECDSA_P256, "Ed25519", ed25519KeyPair))
                .withMessage("ECDSA_P256 key handle must use SHA256withECDSAinP1363Format");
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaKeyHandle(
                        "k1",
                        SignatureAlgorithm.ED25519,
                        "SHA256withECDSAinP1363Format",
                        ecdsaP256KeyPair))
                .withMessage("ED25519 key handle must use Ed25519");
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaKeyHandle(
                        "k1",
                        SignatureAlgorithm.ML_DSA_44,
                        "SHA256withECDSAinP1363Format",
                        ecdsaP256KeyPair))
                .withMessage("ML_DSA_44 placeholder key handle must use Ed25519");
    }

    @Test
    void keyHandleConstructorRejectsBlankStringInputs() throws GeneralSecurityException {
        final KeyPair keyPair = ed25519KeyPair();

        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaKeyHandle(" ", SignatureAlgorithm.ED25519, "Ed25519", keyPair))
                .withMessage("keyId must not be blank");
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaKeyHandle("k1", SignatureAlgorithm.ED25519, " ", keyPair))
                .withMessage("jcaSignatureName must not be blank");
    }

    @Test
    void keyHandleConstructorRejectsEdgePaddedStringInputs() throws GeneralSecurityException {
        final KeyPair keyPair = ed25519KeyPair();

        assertThatIllegalArgumentException()
                .isThrownBy(
                        () -> new JcaKeyHandle(" k1", SignatureAlgorithm.ED25519, "Ed25519", keyPair))
                .withMessage("keyId must not contain leading or trailing whitespace");
        assertThatIllegalArgumentException()
                .isThrownBy(
                        () -> new JcaKeyHandle("k1", SignatureAlgorithm.ED25519, " Ed25519", keyPair))
                .withMessage("jcaSignatureName must not contain leading or trailing whitespace");
    }

    @Test
    void keyHandleConstructorRejectsControlCharactersInStringInputs() throws GeneralSecurityException {
        final KeyPair keyPair = ed25519KeyPair();

        assertThatIllegalArgumentException()
                .isThrownBy(
                        () -> new JcaKeyHandle("k1\nforged", SignatureAlgorithm.ED25519, "Ed25519", keyPair))
                .withMessage("keyId must not contain control characters");
        assertThatIllegalArgumentException()
                .isThrownBy(
                        () -> new JcaKeyHandle("k1", SignatureAlgorithm.ED25519, "Ed25519\nforged", keyPair))
                .withMessage("jcaSignatureName must not contain control characters");
    }

    @Test
    void providerConstructorRejectsNullRequiredConfiguration() {
        assertThatNullPointerException()
                .isThrownBy(() -> new JcaSignatureProvider(null, "Ed25519", null, "Ed25519", "Ed25519"))
                .withMessage("algorithm must not be null");
        assertThatNullPointerException()
                .isThrownBy(() -> new JcaSignatureProvider(
                        SignatureAlgorithm.ED25519, null, null, "Ed25519", "Ed25519"))
                .withMessage("keyPairGeneratorName must not be null");
        assertThatNullPointerException()
                .isThrownBy(() -> new JcaSignatureProvider(
                        SignatureAlgorithm.ED25519, "Ed25519", null, null, "Ed25519"))
                .withMessage("jcaSignatureName must not be null");
        assertThatNullPointerException()
                .isThrownBy(() -> new JcaSignatureProvider(
                        SignatureAlgorithm.ED25519, "Ed25519", null, "Ed25519", null))
                .withMessage("keyFactoryName must not be null");
    }

    @Test
    void providerConstructorRejectsBlankRequiredStringConfiguration() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaSignatureProvider(
                        SignatureAlgorithm.ED25519, " ", null, "Ed25519", "Ed25519"))
                .withMessage("keyPairGeneratorName must not be blank");
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaSignatureProvider(
                        SignatureAlgorithm.ED25519, "Ed25519", null, " ", "Ed25519"))
                .withMessage("jcaSignatureName must not be blank");
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaSignatureProvider(
                        SignatureAlgorithm.ED25519, "Ed25519", null, "Ed25519", " "))
                .withMessage("keyFactoryName must not be blank");
    }

    @Test
    void providerConstructorRejectsEdgePaddedRequiredStringConfiguration() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaSignatureProvider(
                        SignatureAlgorithm.ED25519, " Ed25519", null, "Ed25519", "Ed25519"))
                .withMessage("keyPairGeneratorName must not contain leading or trailing whitespace");
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaSignatureProvider(
                        SignatureAlgorithm.ED25519, "Ed25519", null, " Ed25519", "Ed25519"))
                .withMessage("jcaSignatureName must not contain leading or trailing whitespace");
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaSignatureProvider(
                        SignatureAlgorithm.ED25519, "Ed25519", null, "Ed25519", " Ed25519"))
                .withMessage("keyFactoryName must not contain leading or trailing whitespace");
    }

    @Test
    void providerConstructorRejectsControlCharactersInRequiredStringConfiguration() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaSignatureProvider(
                        SignatureAlgorithm.ED25519, "Ed25519\nforged", null, "Ed25519", "Ed25519"))
                .withMessage("keyPairGeneratorName must not contain control characters");
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaSignatureProvider(
                        SignatureAlgorithm.ED25519, "Ed25519", null, "Ed25519\nforged", "Ed25519"))
                .withMessage("jcaSignatureName must not contain control characters");
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new JcaSignatureProvider(
                        SignatureAlgorithm.ED25519, "Ed25519", null, "Ed25519", "Ed25519\nforged"))
                .withMessage("keyFactoryName must not contain control characters");
    }

    private static KeyPair ed25519KeyPair() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    private static KeyPair ecdsaP256KeyPair() throws GeneralSecurityException {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }
}
