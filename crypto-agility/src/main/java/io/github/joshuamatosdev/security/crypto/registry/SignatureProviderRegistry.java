package io.github.joshuamatosdev.security.crypto.registry;

import io.github.joshuamatosdev.security.crypto.provider.SignatureProvider;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Maps each {@link SignatureAlgorithm} to the one {@link SignatureProvider} that implements it.
 *
 * <p>Refactored from the core platform's {@code KeyProviderRegistry}: algorithm selection drives
 * provider selection. A call site holds the registry, hands it an algorithm, and gets back the
 * provider — it never names a concrete provider class. Adding an algorithm is one new entry; the
 * registry's callers do not change.
 *
 * <p>The registry is immutable after construction and rejects wiring two providers for the same
 * algorithm, so the algorithm-to-provider mapping is unambiguous and fixed at startup.
 */
public final class SignatureProviderRegistry {

    private final Map<SignatureAlgorithm, SignatureProvider> providers;

    /**
     * @param providers the providers to register, one per algorithm
     * @throws IllegalArgumentException if two providers report the same algorithm
     */
    public SignatureProviderRegistry(final List<SignatureProvider> providers) {
        final Map<SignatureAlgorithm, SignatureProvider> map = new EnumMap<>(SignatureAlgorithm.class);
        for (final SignatureProvider provider : providers) {
            final SignatureProvider existing = map.putIfAbsent(provider.algorithm(), provider);
            if (existing != null) {
                throw new IllegalArgumentException(
                        "Duplicate provider for algorithm " + provider.algorithm());
            }
        }
        this.providers = Map.copyOf(map);
    }

    /**
     * Resolves the provider for an algorithm.
     *
     * @param algorithm the algorithm to look up
     * @return the registered provider
     * @throws IllegalArgumentException if no provider is registered for the algorithm
     */
    public SignatureProvider resolve(final SignatureAlgorithm algorithm) {
        final SignatureProvider provider = providers.get(algorithm);
        if (provider == null) {
            throw new IllegalArgumentException("No provider registered for algorithm " + algorithm);
        }
        return provider;
    }
}
