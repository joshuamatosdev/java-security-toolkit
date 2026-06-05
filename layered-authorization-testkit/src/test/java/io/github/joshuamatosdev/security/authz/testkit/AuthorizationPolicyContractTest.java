package io.github.joshuamatosdev.security.authz.testkit;

import io.github.joshuamatosdev.security.authz.service.AuthorizationPolicy;

class AuthorizationPolicyContractTest implements AuthorizationPolicyContract {

    @Override
    public AuthorizationPolicy policy() {
        return new AuthorizationPolicy();
    }
}
