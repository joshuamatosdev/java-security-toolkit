package io.github.joshuamatosdev.security.shared;

import io.github.joshuamatosdev.security.shared.testkit.TypedIdentifierContract;
import java.util.function.Function;

class TenantIdTest implements TypedIdentifierContract<TenantId> {

    @Override
    public Function<String, TenantId> parser() {
        return TenantId::fromString;
    }

    @Override
    public String typeName() {
        return "TenantId";
    }
}
