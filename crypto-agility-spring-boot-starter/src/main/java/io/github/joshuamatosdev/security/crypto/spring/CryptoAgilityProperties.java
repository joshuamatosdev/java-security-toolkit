package io.github.joshuamatosdev.security.crypto.spring;

import io.github.joshuamatosdev.security.crypto.api.SignatureAlgorithm;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Configuration properties for the crypto-agility Spring Boot starter. */
@ConfigurationProperties(prefix = "glyptodon.crypto")
public class CryptoAgilityProperties {

    private boolean enabled = true;
    private SignatureAlgorithm defaultAlgorithm = SignatureAlgorithm.ED25519;
    private String defaultKeyId = "local-ed25519-1";
    private Providers providers = new Providers();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(final boolean enabled) {
        this.enabled = enabled;
    }

    public SignatureAlgorithm getDefaultAlgorithm() {
        return defaultAlgorithm;
    }

    public void setDefaultAlgorithm(final SignatureAlgorithm defaultAlgorithm) {
        this.defaultAlgorithm = defaultAlgorithm;
    }

    public String getDefaultKeyId() {
        return defaultKeyId;
    }

    public void setDefaultKeyId(final String defaultKeyId) {
        this.defaultKeyId = defaultKeyId;
    }

    public Providers getProviders() {
        return providers;
    }

    public void setProviders(final Providers providers) {
        this.providers = providers;
    }

    /** Provider configuration group. */
    public static class Providers {
        private Jca jca = new Jca();

        public Jca getJca() {
            return jca;
        }

        public void setJca(final Jca jca) {
            this.jca = jca;
        }
    }

    /** Local JCA provider configuration. */
    public static class Jca {
        private ProviderToggle ed25519 = new ProviderToggle(true);
        private ProviderToggle ecdsaP256 = new ProviderToggle(false);
        private ProviderToggle mlDsa44Placeholder = new ProviderToggle(false);

        public ProviderToggle getEd25519() {
            return ed25519;
        }

        public void setEd25519(final ProviderToggle ed25519) {
            this.ed25519 = ed25519;
        }

        public ProviderToggle getEcdsaP256() {
            return ecdsaP256;
        }

        public void setEcdsaP256(final ProviderToggle ecdsaP256) {
            this.ecdsaP256 = ecdsaP256;
        }

        public ProviderToggle getMlDsa44Placeholder() {
            return mlDsa44Placeholder;
        }

        public void setMlDsa44Placeholder(final ProviderToggle mlDsa44Placeholder) {
            this.mlDsa44Placeholder = mlDsa44Placeholder;
        }
    }

    /** Boolean provider toggle. */
    public static class ProviderToggle {
        private boolean enabled;

        public ProviderToggle() {
        }

        public ProviderToggle(final boolean enabled) {
            this.enabled = enabled;
        }

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(final boolean enabled) {
            this.enabled = enabled;
        }
    }
}
