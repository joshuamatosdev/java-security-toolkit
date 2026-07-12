package io.github.joshuamatosdev.security.crypto.api;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/** Immutable algorithm-to-provider registry. */
public final class SignatureProviderRegistry {

    private final Map<SignatureAlgorithm, SignatureProvider> providers;

    /**
     * Creates an immutable registry.
     *
     * @throws IllegalArgumentException when two providers report the same algorithm
     */
    public SignatureProviderRegistry(final Collection<? extends SignatureProvider> providers) {
        final Map<SignatureAlgorithm, SignatureProvider> map = new LinkedHashMap<>();
        for (final SignatureProvider provider : Objects.requireNonNull(providers, "providers must not be null")) {
            Objects.requireNonNull(provider, "provider must not be null");
            final SignatureAlgorithm algorithm =
                    Objects.requireNonNull(provider.algorithm(), "provider algorithm must not be null");
            final SignatureProvider existing = map.putIfAbsent(algorithm, provider);
            if (existing != null) {
                throw new IllegalArgumentException("Duplicate provider for algorithm " + algorithm);
            }
        }
        this.providers = Map.copyOf(map);
    }

    /** Resolves the provider for an algorithm. */
    public SignatureProvider resolve(final SignatureAlgorithm algorithm) {
        final SignatureProvider provider = providers.get(algorithm);
        if (provider == null) {
            throw new IllegalArgumentException("No provider registered for algorithm " + algorithm);
        }
        return provider;
    }

    /** Returns whether the registry has a provider for the algorithm. */
    public boolean hasProvider(final SignatureAlgorithm algorithm) {
        return providers.containsKey(algorithm);
    }

    /** Immutable view of providers keyed by algorithm. */
    public Map<SignatureAlgorithm, SignatureProvider> providersByAlgorithm() {
        return providers;
    }
}
