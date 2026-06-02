package io.github.joshuamatosdev.security.authz.web;

import io.github.joshuamatosdev.security.authz.service.AuthorizationDeniedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/**
 * Maps a fine-grained {@link AuthorizationDeniedException} to HTTP 403. The denial reason is returned
 * as-is — a 403 for an authorization failure, never masked as a 404, per the posture in ADR-0001.
 */
@RestControllerAdvice
public class AuthorizationExceptionHandler {

    @ExceptionHandler(AuthorizationDeniedException.class)
    public ResponseEntity<Map<String, String>> onDenied(final AuthorizationDeniedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("denied", ex.reason().name()));
    }
}
