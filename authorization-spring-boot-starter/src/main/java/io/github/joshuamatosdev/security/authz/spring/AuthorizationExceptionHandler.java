package io.github.joshuamatosdev.security.authz.spring;

import io.github.joshuamatosdev.security.authz.service.AuthorizationDeniedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/**
 * Maps a fine-grained {@link AuthorizationDeniedException} to HTTP 403. A known authorization
 * failure is not disguised as a missing resource at this boundary.
 *
 * <p>The body is a generic {@code {"error":"forbidden"}}. The specific {@link
 * io.github.joshuamatosdev.security.authz.decision.DenialReason} is recorded on the server-side audit
 * path (see {@code AuthorizationService.enforce}) and is deliberately NOT returned, so a caller cannot
 * map the policy boundary by reading denial responses.
 *
 * <p>Why this exists: web support isolates header parsing, demo identity resolution, and exception
 * translation at the request boundary.
 */
@RestControllerAdvice
public class AuthorizationExceptionHandler {

    @ExceptionHandler(AuthorizationDeniedException.class)
    public ResponseEntity<Map<String, String>> onDenied() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "forbidden"));
    }
}
