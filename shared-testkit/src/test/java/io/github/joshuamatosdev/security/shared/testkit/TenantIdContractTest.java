package io.github.joshuamatosdev.security.shared.testkit;

import io.github.joshuamatosdev.security.shared.TenantId;
import java.util.function.Function;

class TenantIdContractTest implements TypedIdentifierContract<TenantId> {

    @Override
    public Function<String, TenantId> parser() {
        return TenantId::fromString;
    }

    @Override
    public String typeName() {
        return "TenantId";
    }
}
