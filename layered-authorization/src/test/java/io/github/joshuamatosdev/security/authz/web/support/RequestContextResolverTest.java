package io.github.joshuamatosdev.security.authz.web.support;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.authz.principal.PolicyPrincipal;
import io.github.joshuamatosdev.security.authz.principal.PrincipalType;
import io.github.joshuamatosdev.security.authz.principal.ServicePrincipal;
import io.github.joshuamatosdev.security.authz.principal.UserPrincipal;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Proves the resolver dispatches on caller kind at the boundary: a non-interactive (machine) caller
 * becomes a {@link ServicePrincipal} keyed by its client id, while an interactive caller becomes a
 * {@link UserPrincipal}. Without this, every caller — including a service — was minted as a user with
 * a fabricated email, collapsing the sealed two-kind principal model to one kind.
 *
 * <p>Why this is important to test: authorization bugs become route-level privilege bugs, so the
 * web boundary must prove deny-by-default and scoped access behavior.
 */
class RequestContextResolverTest {

  private final RequestContextResolver resolver = new RequestContextResolver(true);

  @Test
  void aServiceMarkedCallerResolvesToAServicePrincipalKeyedByClientId() {
    Authentication serviceCaller =
        new UsernamePasswordAuthenticationToken(
            "svc-report",
            "n/a",
            List.of(new SimpleGrantedAuthority(RequestContextResolver.SERVICE_CALLER_AUTHORITY)));

    PolicyPrincipal principal = resolver.resolve(serviceCaller).principal();

    assertThat(principal).isInstanceOf(ServicePrincipal.class);
    assertThat(principal.principalType()).isEqualTo(PrincipalType.SERVICE);
    assertThat(principal.principalKey()).isEqualTo("svc-report");
  }

  @Test
  void aServiceMarkedCallerCannotInheritACollidingUserProfile() {
    Authentication serviceCaller =
        new UsernamePasswordAuthenticationToken(
            DemoAccounts.ADMIN_USERNAME,
            "n/a",
            List.of(
                new SimpleGrantedAuthority("ROLE_PLATFORM_ADMIN"),
                new SimpleGrantedAuthority(RequestContextResolver.SERVICE_CALLER_AUTHORITY)));

    RequestContextResolver.ResolvedRequestContext resolved = resolver.resolve(serviceCaller);

    assertThat(resolved.principal()).isInstanceOf(ServicePrincipal.class);
    assertThat(resolved.trustedProfile()).isFalse();
  }

  @Test
  void anInteractiveCallerResolvesToAUserPrincipal() {
    Authentication user =
        new UsernamePasswordAuthenticationToken(
            "member", "n/a", List.of(new SimpleGrantedAuthority("ROLE_MEMBER")));

    PolicyPrincipal principal = resolver.resolve(user).principal();

    assertThat(principal).isInstanceOf(UserPrincipal.class);
    assertThat(principal.principalType()).isEqualTo(PrincipalType.USER);
    assertThat(principal.principalKey()).isEqualTo("member");
  }

  @Test
  void malformedInteractivePrincipalNameFailsClosedInsteadOfCrashingResolution() {
    Authentication user =
        new UsernamePasswordAuthenticationToken(
            "member\nforged", "n/a", List.of(new SimpleGrantedAuthority("ROLE_MEMBER")));

    RequestContextResolver.ResolvedRequestContext resolved = resolver.resolve(user);

    assertThat(resolved.principal()).isInstanceOf(UserPrincipal.class);
    assertThat(resolved.principal().principalKey()).isEqualTo("invalid-principal");
    assertThat(resolved.trustedProfile()).isFalse();
  }

  @Test
  void nullInteractivePrincipalNameFailsClosedInsteadOfCrashingResolution() {
    Authentication user = new NullNameAuthentication("n/a", List.of(new SimpleGrantedAuthority("ROLE_MEMBER")));

    RequestContextResolver.ResolvedRequestContext resolved = resolver.resolve(user);

    assertThat(resolved.principal()).isInstanceOf(UserPrincipal.class);
    assertThat(resolved.principal().principalKey()).isEqualTo("invalid-principal");
    assertThat(resolved.trustedProfile()).isFalse();
  }

  @Test
  void malformedServicePrincipalNameFailsClosedInsteadOfCrashingResolution() {
    Authentication serviceCaller =
        new UsernamePasswordAuthenticationToken(
            "svc-report\nforged",
            "n/a",
            List.of(new SimpleGrantedAuthority(RequestContextResolver.SERVICE_CALLER_AUTHORITY)));

    RequestContextResolver.ResolvedRequestContext resolved = resolver.resolve(serviceCaller);

    assertThat(resolved.principal()).isInstanceOf(ServicePrincipal.class);
    assertThat(resolved.principal().principalKey()).isEqualTo("invalid-principal");
    assertThat(resolved.trustedProfile()).isFalse();
  }

  @Test
  void nullAuthorityValueFailsClosedInsteadOfCrashingResolution() {
    Authentication user =
        new UsernamePasswordAuthenticationToken("member", "n/a", List.of(() -> null));

    RequestContextResolver.ResolvedRequestContext resolved = resolver.resolve(user);

    assertThat(resolved.principal()).isInstanceOf(UserPrincipal.class);
    assertThat(resolved.trustedProfile()).isFalse();
  }

  private static final class NullNameAuthentication extends AbstractAuthenticationToken {

    private final Object credentials;

    private NullNameAuthentication(Object credentials, List<SimpleGrantedAuthority> authorities) {
      super(authorities);
      this.credentials = credentials;
      setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
      return credentials;
    }

    @Override
    public Object getPrincipal() {
      return null;
    }

    @Override
    public String getName() {
      return null;
    }
  }
}
