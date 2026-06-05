package io.github.joshuamatosdev.security.shared;

import io.github.joshuamatosdev.security.shared.testkit.TypedIdentifierContract;
import java.util.function.Function;

class OrganizationIdTest implements TypedIdentifierContract<OrganizationId> {

    @Override
    public Function<String, OrganizationId> parser() {
        return OrganizationId::fromString;
    }

    @Override
    public String typeName() {
        return "OrganizationId";
    }
}
