package io.github.joshuamatosdev.security.edge.chain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;

class BrowserRouteTableTest {

  @Test
  void defaultsAreImmutableAndKeepTheNarrowAdminExceptionFirst() {
    var rules = BrowserRouteTable.defaults().rules();

    assertThat(rules)
        .extracting(rule -> rule.matcher().paths())
        .containsSubsequence(
            List.of("/api/admin/audit-export"),
            List.of("/api/admin/**"));
    assertThatThrownBy(() -> rules.add(rules.getFirst()))
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> rules.getFirst().matcher().paths().add("/mutable"))
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void customRoutesAreAcceptedWithoutChangingTheChainAlgorithm() {
    var custom =
        new BrowserRouteTable(
            List.of(
                new BrowserRouteTable.BrowserRoute(
                    new BrowserRouteTable.MethodPaths(
                        HttpMethod.GET, List.of("/custom/status")),
                    BrowserRouteTable.StandardAuthorization.PERMIT_ALL,
                    List.of(HttpMethod.GET))));

    assertThat(custom.rules()).singleElement().satisfies(
        rule -> assertThat(rule.matcher().paths()).containsExactly("/custom/status"));
  }
}
