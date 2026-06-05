package io.github.joshuamatosdev.security.authz.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Method;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.Repository;

/**
 * Document Repository Boundary test coverage.
 *
 * <p>Why this is important to test: repository boundaries must keep resource ownership facts
 * database-owned instead of invented by callers.
 */
class DocumentRepositoryBoundaryTest {

    @Test
    void repositoryDoesNotExposeUnscopedJpaRepositoryMethods() {
        assertThat(Repository.class).isAssignableFrom(DocumentRepository.class);
        assertThat(JpaRepository.class.isAssignableFrom(DocumentRepository.class))
                .as("layered authorization must expose only tenant-scoped repository methods")
                .isFalse();
        assertThat(Arrays.stream(DocumentRepository.class.getMethods()).map(Method::getName))
                .doesNotContain("findAll", "findById", "deleteById", "deleteAll", "deleteAllById");
    }
}
