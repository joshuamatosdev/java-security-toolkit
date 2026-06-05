package io.github.joshuamatosdev.security.authz.web.document;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import io.github.joshuamatosdev.security.authz.persistence.DocumentRepository;
import io.github.joshuamatosdev.security.shared.ResourceId;
import org.junit.jupiter.api.Test;

/**
 * Document Directory test coverage.
 *
 * <p>Why this is important to test: authorization bugs become route-level privilege bugs, so the
 * web boundary must prove deny-by-default and scoped access behavior.
 */
class DocumentDirectoryTest {

    private static final ResourceId DOCUMENT =
        ResourceId.fromString("33333333-3333-3333-3333-333333333333");

    @Test
    void deleteKeepsTheTenantPredicateOnTheWriteOperation() {
        final DocumentRepository repository = mock(DocumentRepository.class);
        final DocumentDirectory directory = new DocumentDirectory(repository);

        directory.delete(DocumentDirectory.ACME, DOCUMENT);

        verify(repository).deleteByIdAndTenantId(DOCUMENT.value(), DocumentDirectory.ACME.value());
        verifyNoMoreInteractions(repository);
    }

    @Test
    void createRejectsMalformedOwnerPrincipalKeyBeforeSaving() {
        final DocumentRepository repository = mock(DocumentRepository.class);
        final DocumentDirectory directory = new DocumentDirectory(repository);

        assertThatThrownBy(() ->
                directory.create(DocumentDirectory.ACME, DocumentDirectory.ENGINEERING, "member\nforged"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("ownerPrincipalKey must not contain control characters");

        verify(repository, never()).save(any());
    }
}
