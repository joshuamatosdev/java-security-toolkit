package example.service;

import io.github.joshuamatosdev.security.authz.decision.DenialReason;
import io.github.joshuamatosdev.security.authz.policy.Action;
import io.github.joshuamatosdev.security.authz.request.ProtectedResource;
import io.github.joshuamatosdev.security.authz.request.RequestContext;
import io.github.joshuamatosdev.security.authz.service.AuthorizationService;
import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.ResourceId;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Tenant-scoped documents behind both authorization gates and RLS — the composed seam this example
 * exists to prove.
 *
 * <p>Layer order per request: the coarse route gate (SecurityConfig) already required a role, the
 * binding filter bound the verified tenant, and every SQL statement below runs against the
 * RLS-scoped pool — there is deliberately no {@code WHERE tenant_id} anywhere. On top of that
 * data-plane boundary, each single-document operation asks the {@link AuthorizationService} for a
 * fine-grained, audited decision.
 *
 * <p>A cross-tenant probe never reaches the policy: RLS returns no row, the attempt is audited as
 * {@code RESOURCE_NOT_FOUND}, and the caller sees the same 404 a nonexistent id produces — a
 * foreign tenant learns nothing about which ids exist.
 */
@RestController
@RequestMapping("/documents")
class DocumentController {

    private final JdbcClient jdbc;
    private final AuthorizationService authorization;

    DocumentController(final JdbcClient jdbc, final AuthorizationService authorization) {
        this.jdbc = jdbc;
        this.authorization = authorization;
    }

    record DocumentResponse(UUID id, String title, String body, String owner) {}

    record NewDocument(String title, String body) {}

    private record DocumentRow(UUID id, UUID organizationId, String ownerSubject, String title, String body) {

        DocumentResponse toResponse() {
            return new DocumentResponse(id, title, body, ownerSubject);
        }

        ProtectedResource toResource(final RequestContext context) {
            return new ProtectedResource(
                    new ResourceId(id),
                    context.tenantId(),
                    organizationId == null ? null : new OrganizationId(organizationId),
                    ownerSubject);
        }
    }

    /**
     * Listing is scoped by the data plane alone: RLS decides which rows exist for this session.
     * Per-resource policy runs on single-document access, where there is a concrete resource to
     * decide about.
     */
    @GetMapping
    List<DocumentResponse> list(final JwtAuthenticationToken authentication) {
        RequestContexts.fromJwt(authentication);
        return jdbc.sql("SELECT id, organization_id, owner_subject, title, body FROM document ORDER BY title")
                .query(DocumentRow.class)
                .list()
                .stream()
                .map(DocumentRow::toResponse)
                .toList();
    }

    @GetMapping("/{id}")
    DocumentResponse get(final JwtAuthenticationToken authentication, @PathVariable final UUID id) {
        final RequestContext context = RequestContexts.fromJwt(authentication);
        final DocumentRow row = loadOrAuditNotFound(context, id, Action.READ);
        authorization.enforce(context, row.toResource(context), Action.READ);
        return row.toResponse();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    DocumentResponse create(final JwtAuthenticationToken authentication, @RequestBody final NewDocument document) {
        if (document.title() == null || document.title().isBlank()
                || document.body() == null || document.body().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "title and body are required");
        }
        final RequestContext context = RequestContexts.fromJwt(authentication);
        // CREATE is decided against the prospective resource's placement. The decision needs a
        // resource id for the audit record only — the persisted id is minted by the database's
        // id_v7 default, never by application code.
        final ProtectedResource prospective = new ProtectedResource(
                new ResourceId(UUID.randomUUID()),
                context.tenantId(),
                context.organizationId(),
                context.principalKey());
        authorization.enforce(context, prospective, Action.CREATE);
        // id, tenant_id, and organization_id are database-stamped: id from the id_v7 domain
        // default, the other two from the verified session claims.
        return jdbc.sql("INSERT INTO document (owner_subject, title, body) VALUES (:owner, :title, :body) "
                        + "RETURNING id, organization_id, owner_subject, title, body")
                .param("owner", context.principalKey())
                .param("title", document.title())
                .param("body", document.body())
                .query(DocumentRow.class)
                .single()
                .toResponse();
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void delete(final JwtAuthenticationToken authentication, @PathVariable final UUID id) {
        final RequestContext context = RequestContexts.fromJwt(authentication);
        final DocumentRow row = loadOrAuditNotFound(context, id, Action.DELETE);
        authorization.enforce(context, row.toResource(context), Action.DELETE);
        jdbc.sql("DELETE FROM document WHERE id = :id").param("id", id).update();
    }

    /**
     * RLS runs first: a row another tenant owns simply does not exist for this session. The
     * attempt still lands in the authorization audit trail ({@code RESOURCE_NOT_FOUND}, not a
     * 403), and the HTTP answer is indistinguishable from a nonexistent id.
     */
    private DocumentRow loadOrAuditNotFound(final RequestContext context, final UUID id, final Action action) {
        final Optional<DocumentRow> row = jdbc
                .sql("SELECT id, organization_id, owner_subject, title, body FROM document WHERE id = :id")
                .param("id", id)
                .query(DocumentRow.class)
                .optional();
        if (row.isEmpty()) {
            authorization.auditDeny(
                    context,
                    new ProtectedResource(new ResourceId(id), context.tenantId(), null, null),
                    action,
                    DenialReason.RESOURCE_NOT_FOUND);
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        return row.get();
    }
}
