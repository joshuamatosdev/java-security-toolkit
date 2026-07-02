package io.github.joshuamatosdev.security.shared;

import io.github.joshuamatosdev.security.shared.testkit.TypedIdentifierContract;
import java.util.function.Function;

class TeamIdTest implements TypedIdentifierContract<TeamId> {

    @Override
    public Function<String, TeamId> parser() {
        return TeamId::fromString;
    }

    @Override
    public String typeName() {
        return "TeamId";
    }
}
