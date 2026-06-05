package io.github.joshuamatosdev.security.crypto.provider;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.crypto.key.KeyHandle;
import io.github.joshuamatosdev.security.crypto.registry.AlgorithmFamily;
import io.github.joshuamatosdev.security.crypto.registry.SignatureAlgorithm;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * Pins the distinction behind {@link SignatureAlgorithm#fipsApproved()}: the flag annotates the
 * approved <em>algorithm identity</em> (FIPS&nbsp;204 approves ML-DSA-44), not a CMVP-validated
 * <em>implementation</em>. The post-quantum slot currently ships an Ed25519 stand-in, so {@code
 * fipsApproved() && family() == POST_QUANTUM} must not be read as "real post-quantum protection is
 * active". A runtime FIPS/PQC gate has to confirm the wired provider is the real algorithm too.
 *
 * <p>This is also the tripwire for the placeholder: when a genuine ML-DSA provider replaces the
 * stand-in, {@link #thePostQuantumSlotStillRunsAClassicalStandIn} will fail (an Ed25519 verifier
 * cannot check an ML-DSA signature), forcing a deliberate update to this FIPS narrative.
 *
 * <p>Why this is important to test: algorithm migration depends on identical signing semantics
 * across providers and robust rejection of invalid key or signature material.
 */
class FipsApprovedIsAlgorithmIdentityNotRuntimeValidationTest {

  @Test
  void mlDsa44IsFipsApprovedAsAnAlgorithmIdentity() {
    assertThat(SignatureAlgorithm.ML_DSA_44.fipsApproved()).isTrue();
    assertThat(SignatureAlgorithm.ML_DSA_44.family()).isEqualTo(AlgorithmFamily.POST_QUANTUM);
  }

  @Test
  void thePostQuantumSlotStillRunsAClassicalStandIn() {
    SignatureProvider placeholder = SignatureProviders.postQuantumPlaceholder();
    assertThat(placeholder.algorithm()).isEqualTo(SignatureAlgorithm.ML_DSA_44);

    KeyHandle handle = placeholder.generateKey("pqc-1");
    byte[] payload = "agility".getBytes(StandardCharsets.UTF_8);
    byte[] signature = handle.sign(payload);

    // A genuine ML-DSA signature could not be verified by an Ed25519 verifier. This passing proves
    // the slot signs with the classical stand-in, so a FIPS/PQC runtime gate cannot trust the
    // algorithm's fipsApproved() flag alone to mean post-quantum protection is in force.
    assertThat(SignatureProviders.ed25519().verify(handle.publicKey(), payload, signature)).isTrue();
  }
}
