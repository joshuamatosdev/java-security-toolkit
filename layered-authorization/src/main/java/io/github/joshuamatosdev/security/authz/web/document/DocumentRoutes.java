package io.github.joshuamatosdev.security.authz.web.document;

/**
 * Document HTTP route templates.
 */
public final class DocumentRoutes {

    public static final String DOCUMENTS_PATH = "/api/documents";
    public static final String DOCUMENT_ID_PATH = "/{id}";
    public static final String DOCUMENT_ID_ROUTE = DOCUMENTS_PATH + DOCUMENT_ID_PATH;
    public static final String DOCUMENTS_DESCENDANTS_PATTERN = DOCUMENTS_PATH + "/**";

    private DocumentRoutes() {}
}
