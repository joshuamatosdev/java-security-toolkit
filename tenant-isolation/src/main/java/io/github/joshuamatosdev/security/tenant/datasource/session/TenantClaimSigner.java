package io.github.joshuamatosdev.security.tenant.datasource.session;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Signs tenant session claims consumed by the PostgreSQL RLS verifier. The backing secret must
 * match the DB-private verifier secret installed with the schema.
 *
 * <p>A claim is {@code v2:<tenant_uuid>:<exp_epoch_seconds>:<hmac_sha256>}, where the HMAC covers
 * {@code v2:<tenant_uuid>:<exp_epoch_seconds>}. The {@code exp} field bounds the claim's lifetime:
 * the verifier rejects an expired claim, so a claim captured (e.g. from query-parameter logs) cannot
 * be replayed once it ages out, and the per-borrow {@code exp} makes each emitted claim distinct.
 * {@code exp} is inside the signed payload, so it cannot be extended without the secret.
 *
 * <p>The TTL must exceed the longest single connection borrow: the claim is re-minted on every borrow
 * and verified per statement, so it must stay valid for that borrow's whole duration.
 */
public final class TenantClaimSigner {

    private static final String VERSION = "v2";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int MIN_SECRET_BYTES = 32;

    private final byte[] secret;
    private final Duration claimTtl;
    private final Clock clock;

    /**
     * Creates a signer for PostgreSQL tenant session claims.
     *
     * <p>The clock is injectable so tests can assert deterministic expiry behavior without
     * weakening production's use of UTC wall-clock time.
     *
     * @param secret HMAC secret shared with the database verifier; must be at least 32 UTF-8 bytes
     * @param claimTtl how long each per-borrow claim remains valid
     * @param clock clock used to compute the signed expiry timestamp
     * @throws IllegalArgumentException when the secret is missing or weak, or the TTL is not positive
     */
    public TenantClaimSigner(final String secret, final Duration claimTtl, final Clock clock) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalArgumentException("tenant claim secret must be populated");
        }
        final byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
        if (secretBytes.length < MIN_SECRET_BYTES) {
            throw new IllegalArgumentException("tenant claim secret must be at least 32 bytes");
        }
        this.claimTtl = Objects.requireNonNull(claimTtl, "claimTtl");
        if (claimTtl.isZero() || claimTtl.isNegative()) {
            throw new IllegalArgumentException("tenant claim TTL must be positive");
        }
        this.clock = Objects.requireNonNull(clock, "clock");
        this.secret = secretBytes.clone();
    }

    /**
     * Builds and signs a versioned tenant claim for one connection borrow.
     *
     * <p>The expiry timestamp is inside the signed payload, so a caller cannot extend the lifetime
     * without knowing the shared secret. The method has package visibility because only the
     * datasource binding layer should emit DB-consumable tenant claims.
     *
     * @param tenantUuid tenant identifier to place in the signed claim
     * @return {@code v2:<tenant_uuid>:<exp_epoch_seconds>:<hmac_sha256>}
     */
    String sign(final UUID tenantUuid) {
        final long exp = clock.instant().plus(claimTtl).getEpochSecond();
        final String payload = VERSION + ":" + Objects.requireNonNull(tenantUuid, "tenantUuid") + ":" + exp;
        return payload + ":" + HexFormat.of().formatHex(hmac(payload));
    }

    /**
     * Computes the HMAC-SHA256 signature for the signed claim payload.
     *
     * <p>A new {@link Mac} is created per call because {@code Mac} instances are mutable and not
     * thread-safe; this signer is a singleton Spring bean and can be used concurrently by many
     * connection borrows.
     *
     * @param payload signed claim payload excluding the final signature field
     * @return raw HMAC bytes
     */
    private byte[] hmac(final String payload) {
        try {
            final Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(secret, HMAC_ALGORITHM));
            return mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("tenant claim signing failed", ex);
        }
    }
}

