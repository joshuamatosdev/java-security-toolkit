package io.github.joshuamatosdev.security.shared;

import io.github.joshuamatosdev.security.shared.testkit.TypedIdentifierContract;
import java.util.function.Function;

class ResourceIdTest implements TypedIdentifierContract<ResourceId> {

    @Override
    public Function<String, ResourceId> parser() {
        return ResourceId::fromString;
    }

    @Override
    public String typeName() {
        return "ResourceId";
    }
}
