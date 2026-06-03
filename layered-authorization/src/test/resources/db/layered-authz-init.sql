-- Test schema authority for layered-authorization.
-- Mirrors tenant-isolation's PG18 identifier rule: primary keys are database-owned UUIDv7 values.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authz_app') THEN
        CREATE ROLE authz_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT NOCREATEDB NOCREATEROLE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authz_user') THEN
        CREATE ROLE authz_user LOGIN NOSUPERUSER NOBYPASSRLS INHERIT NOCREATEDB NOCREATEROLE
            PASSWORD 'local_dev_only';
    END IF;
    GRANT authz_app TO authz_user;
    GRANT USAGE ON SCHEMA public TO authz_app;
    GRANT USAGE ON SCHEMA public TO authz_user;
END
$$;

CREATE DOMAIN id_v7 AS uuid DEFAULT uuidv7();

CREATE TABLE document (
    id                  id_v7 PRIMARY KEY,
    tenant_id           uuid NOT NULL,
    organization_id     uuid,
    owner_principal_key text
);

GRANT SELECT, DELETE ON document TO authz_app;
GRANT INSERT (tenant_id, organization_id, owner_principal_key) ON document TO authz_app;
