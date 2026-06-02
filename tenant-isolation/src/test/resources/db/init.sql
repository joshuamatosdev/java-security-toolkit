-- Container bootstrap, run as the superuser before the app connects (docker-entrypoint-initdb.d).
-- Mirrors the production pattern: init-db SQL is the schema authority (Flyway is a no-op on a
-- fresh container). The runtime pool authenticates as the non-superuser tenant_user, so RLS engages.

-- 1) Role mesh: tenant_app holds privileges (NOLOGIN owner); tenant_user (the runtime pool) inherits
--    them and is NOSUPERUSER NOBYPASSRLS. Production additionally splits out _seed_runner and
--    _migrator tiers; the runtime isolation guarantee only needs these two.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tenant_app') THEN
        CREATE ROLE tenant_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT NOCREATEDB NOCREATEROLE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tenant_user') THEN
        CREATE ROLE tenant_user LOGIN NOSUPERUSER NOBYPASSRLS INHERIT NOCREATEDB NOCREATEROLE
            PASSWORD 'local_dev_only';
    END IF;
    GRANT tenant_app TO tenant_user;
    GRANT USAGE ON SCHEMA public TO tenant_app;
    GRANT USAGE ON SCHEMA public TO tenant_user;
END
$$;

-- 2) Tenant-scoped table with Row-Level Security.
--    tenant_id is stamped from the session GUC on insert (a caller cannot forge another tenant's id);
--    reads are filtered by the GUC; writes are checked by the same expression; app.bypass_rls is the
--    audited system-ops escape.
CREATE TABLE document (
    id        uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT current_setting('app.current_tenant', true)::uuid,
    title     text NOT NULL,
    body      text NOT NULL
);

ALTER TABLE document ENABLE ROW LEVEL SECURITY;
ALTER TABLE document FORCE ROW LEVEL SECURITY;

CREATE POLICY p_tenant_isolation ON document
    FOR ALL TO public
    USING (
        tenant_id = current_setting('app.current_tenant', true)::uuid
        OR current_setting('app.bypass_rls', true) = 'on'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant', true)::uuid
        OR current_setting('app.bypass_rls', true) = 'on'
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON document TO tenant_app;
