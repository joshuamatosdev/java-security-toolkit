package example;

import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Tenant-scoped notes with zero tenant plumbing.
 *
 * <p>There is deliberately no {@code WHERE tenant_id} or {@code WHERE organization_id} anywhere,
 * no tenant column in the request or response, and no way to express a cross-tenant write. The
 * datasource proxy binds the signed claims on every borrow and PostgreSQL row-level security
 * scopes what this SQL can see and stamp — the integration tests prove it.
 */
@RestController
@RequestMapping("/notes")
class NoteController {

    private final JdbcClient jdbc;

    NoteController(final JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    record NoteResponse(UUID id, String title, String body) {}

    record NewNote(String title, String body) {}

    @GetMapping
    List<NoteResponse> list() {
        return jdbc.sql("SELECT id, title, body FROM note ORDER BY title")
                .query(NoteResponse.class)
                .list();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    NoteResponse create(@RequestBody final NewNote note) {
        if (note.title() == null || note.title().isBlank() || note.body() == null || note.body().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "title and body are required");
        }
        // id, tenant_id, and organization_id are database-stamped: id from the id_v7 domain
        // default, the other two from the verified session claims.
        return jdbc.sql("INSERT INTO note (title, body) VALUES (:title, :body) RETURNING id, title, body")
                .param("title", note.title())
                .param("body", note.body())
                .query(NoteResponse.class)
                .single();
    }
}
