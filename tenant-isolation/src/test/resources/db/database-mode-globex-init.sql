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
END
$$;

CREATE SCHEMA IF NOT EXISTS tenant_security;
REVOKE ALL ON SCHEMA tenant_security FROM PUBLIC;

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA tenant_security;
DO $$
DECLARE
    pgcrypto_schema name;
BEGIN
    SELECT namespace.nspname INTO pgcrypto_schema
    FROM pg_extension extension
    JOIN pg_namespace namespace ON namespace.oid = extension.extnamespace
    WHERE extension.extname = 'pgcrypto';

    IF pgcrypto_schema <> 'tenant_security' THEN
        RAISE EXCEPTION 'pgcrypto extension must be installed in tenant_security, found in %', pgcrypto_schema;
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS tenant_security.claim_secret (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    secret    text NOT NULL CHECK (octet_length(secret) >= 32)
);

INSERT INTO tenant_security.claim_secret (singleton, secret)
VALUES (true, 'local-dev-tenant-claim-secret-not-production-32-bytes')
ON CONFLICT (singleton) DO UPDATE SET secret = EXCLUDED.secret;

REVOKE ALL ON ALL TABLES IN SCHEMA tenant_security FROM PUBLIC;

CREATE OR REPLACE FUNCTION tenant_security.current_tenant_id()
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, tenant_security
AS $$
DECLARE
    claim text := current_setting('app.tenant_claim', true);
    claim_version text;
    tenant_text text;
    claim_exp_text text;
    claim_signature text;
    expected_signature text;
    secret_value text;
    compare_key text;
BEGIN
    IF claim IS NULL OR claim = '' THEN
        RETURN NULL;
    END IF;

    claim_version := split_part(claim, ':', 1);
    tenant_text := split_part(claim, ':', 2);
    claim_exp_text := split_part(claim, ':', 3);
    claim_signature := split_part(claim, ':', 4);

    IF claim_version <> 'v2'
        OR tenant_text = ''
        OR claim_exp_text = ''
        OR claim_signature = ''
        OR claim <> claim_version || ':' || tenant_text || ':' || claim_exp_text || ':' || claim_signature THEN
        RETURN NULL;
    END IF;

    IF tenant_text !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        OR claim_exp_text !~ '^[0-9]{1,15}$'
        OR claim_signature !~* '^[0-9a-f]{64}$' THEN
        RETURN NULL;
    END IF;

    SELECT secret INTO secret_value
    FROM tenant_security.claim_secret
    WHERE singleton;

    IF secret_value IS NULL THEN
        RETURN NULL;
    END IF;

    expected_signature := encode(
        tenant_security.hmac(claim_version || ':' || tenant_text || ':' || claim_exp_text, secret_value, 'sha256'),
        'hex'
    );

    compare_key := encode(tenant_security.gen_random_bytes(32), 'hex');
    IF tenant_security.hmac(lower(claim_signature), compare_key, 'sha256')
        <> tenant_security.hmac(expected_signature, compare_key, 'sha256') THEN
        RETURN NULL;
    END IF;

    IF claim_exp_text::bigint <= extract(epoch FROM clock_timestamp()) THEN
        RETURN NULL;
    END IF;

    RETURN tenant_text::uuid;
END
$$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA tenant_security FROM PUBLIC;
GRANT USAGE ON SCHEMA tenant_security TO tenant_app;
GRANT EXECUTE ON FUNCTION tenant_security.current_tenant_id() TO tenant_app;

CREATE DOMAIN id_v7 AS uuid DEFAULT uuidv7();

CREATE TABLE document (
    id        id_v7 PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT tenant_security.current_tenant_id(),
    title     text NOT NULL,
    body      text NOT NULL,
    CONSTRAINT document_tenant_check CHECK (tenant_id = '0190a000-0000-7000-8000-0000000000b2'::uuid)
);

GRANT SELECT, DELETE ON document TO tenant_app;
GRANT INSERT (title, body), UPDATE (title, body) ON document TO tenant_app;
