package io.github.joshuamatosdev.security.supplychain.testkit;

import io.github.joshuamatosdev.security.supplychain.policy.ActionPinPolicy;

class ActionPinPolicyContractTest implements ActionPinPolicyContract {

    @Override
    public ActionPinPolicy policy() {
        return new ActionPinPolicy();
    }
}
