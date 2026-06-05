package io.github.joshuamatosdev.security.supplychain.policy;

import io.github.joshuamatosdev.security.supplychain.testkit.BaseImagePolicyContract;

class BaseImagePolicyContractTest implements BaseImagePolicyContract {

  @Override
  public BaseImagePolicy policy() {
    return new BaseImagePolicy();
  }
}
