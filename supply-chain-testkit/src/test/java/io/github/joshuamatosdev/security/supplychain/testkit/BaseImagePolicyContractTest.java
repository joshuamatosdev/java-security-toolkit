package io.github.joshuamatosdev.security.supplychain.testkit;

import io.github.joshuamatosdev.security.supplychain.policy.BaseImagePolicy;

class BaseImagePolicyContractTest implements BaseImagePolicyContract {

    @Override
    public BaseImagePolicy policy() {
        return new BaseImagePolicy();
    }
}
