-- Adopter copy of the tenant-isolation reference DDL (walkthrough step 4), adapted for this
-- application's one tenant-scoped table: document. Source of truth for the pattern:
-- tenant-isolation/src/test/resources/db/init.sql. Omitted here because this application does not
-- use them: the system-writer tier (system_audit) and cross-tenant read entitlements (read_grant +
-- p_entitled_read) — copy those sections from the reference when you adopt them.
--
-- Run as the superuser before the app connects (docker-entrypoint-initdb.d). The runtime pool
-- authenticates as the non-superuser tenant_user, so RLS engages.

-- 1) Role mesh: tenant_app holds ordinary tenant privileges; tenant_user is the runtime pool.
--    tenant_bypass is a NOLOGIN marker role for system-operations reads; tenant_ops_user is the
--    separate system-ops pool and is intentionally granted SELECT only.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tenant_app') THEN
        CREATE ROLE tenant_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT NOCREATEDB NOCREATEROLE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tenant_bypass') THEN
        CREATE ROLE tenant_bypass NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT NOCREATEDB NOCREATEROLE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tenant_user') THEN
        CREATE ROLE tenant_user LOGIN NOSUPERUSER NOBYPASSRLS INHERIT NOCREATEDB NOCREATEROLE
            PASSWORD 'local_dev_only';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tenant_ops_user') THEN
        CREATE ROLE tenant_ops_user LOGIN NOSUPERUSER NOBYPASSRLS INHERIT NOCREATEDB NOCREATEROLE
            PASSWORD 'local_dev_only';
    END IF;
    GRANT tenant_app TO tenant_user;
    GRANT tenant_bypass TO tenant_ops_user;
    GRANT USAGE ON SCHEMA public TO tenant_app;
    GRANT USAGE ON SCHEMA public TO tenant_user;
    GRANT USAGE ON SCHEMA public TO tenant_bypass;
END
$$;

-- 2) Tenant claim verifier — copied verbatim from the reference DDL.
--    app.tenant_claim is still a mutable session setting, so the policy never trusts it directly.
--    The value must be v2:<tenant_uuid>:<exp_epoch_seconds>:<hmac_sha256>, signed with a DB-private
--    secret over "v2:<tenant_uuid>:<exp_epoch_seconds>". The verifier checks the HMAC and then the
--    expiry: exp is inside the signed payload (so it cannot be extended without the secret), which
--    bounds replay of a captured claim to its short lifetime. Ordinary tenant roles can execute the
--    verifier but cannot read the secret or compute a valid claim for another tenant from inside SQL.
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

-- Fictional local-only test secret. Production installs this row from secret management and keeps
-- the Java signer secret and DB verifier secret in sync.
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

    -- Timing-safe comparison via the double-HMAC pattern: re-MAC both signatures under a fresh
    -- random key so the byte positions being compared are unpredictable per call, denying any
    -- timing oracle that would otherwise leak how many leading characters of a forged signature
    -- matched. (PostgreSQL has no native constant-time text comparison.)
    compare_key := encode(tenant_security.gen_random_bytes(32), 'hex');
    IF tenant_security.hmac(lower(claim_signature), compare_key, 'sha256')
        <> tenant_security.hmac(expected_signature, compare_key, 'sha256') THEN
        RETURN NULL;
    END IF;

    -- Signature verified, so the exp field is authentic. Reject a claim at or past its lifetime
    -- using wall-clock time, not transaction-start time, so a long transaction cannot continue to
    -- use a claim after it has expired.
    IF claim_exp_text::bigint <= extract(epoch FROM clock_timestamp())::bigint THEN
        RETURN NULL;
    END IF;

    RETURN tenant_text::uuid;
END
$$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA tenant_security FROM PUBLIC;
GRANT USAGE ON SCHEMA tenant_security TO tenant_app;
GRANT USAGE ON SCHEMA tenant_security TO tenant_bypass;
GRANT EXECUTE ON FUNCTION tenant_security.current_tenant_id() TO tenant_app;
GRANT EXECUTE ON FUNCTION tenant_security.current_tenant_id() TO tenant_bypass;

-- 2b) Organization claim verifier — copied verbatim from the reference DDL.
--     app.org_claim carries the organization dimension of the binding: same signed shape and secret
--     as the tenant claim but its own version marker v2o inside the signed payload, so a captured
--     tenant claim replayed into app.org_claim (or an organization claim into app.tenant_claim)
--     fails the version check before the signature is even compared. NULL means the session is
--     organization-unscoped; organization scope subdivides a verified tenant, it never replaces the
--     tenant boundary.
CREATE OR REPLACE FUNCTION tenant_security.current_org_id()
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, tenant_security
AS $$
DECLARE
    claim text := current_setting('app.org_claim', true);
    claim_version text;
    org_text text;
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
    org_text := split_part(claim, ':', 2);
    claim_exp_text := split_part(claim, ':', 3);
    claim_signature := split_part(claim, ':', 4);

    IF claim_version <> 'v2o'
        OR org_text = ''
        OR claim_exp_text = ''
        OR claim_signature = ''
        OR claim <> claim_version || ':' || org_text || ':' || claim_exp_text || ':' || claim_signature THEN
        RETURN NULL;
    END IF;

    IF org_text !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
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
        tenant_security.hmac(claim_version || ':' || org_text || ':' || claim_exp_text, secret_value, 'sha256'),
        'hex'
    );

    -- Same timing-safe double-HMAC comparison as tenant_security.current_tenant_id().
    compare_key := encode(tenant_security.gen_random_bytes(32), 'hex');
    IF tenant_security.hmac(lower(claim_signature), compare_key, 'sha256')
        <> tenant_security.hmac(expected_signature, compare_key, 'sha256') THEN
        RETURN NULL;
    END IF;

    IF claim_exp_text::bigint <= extract(epoch FROM clock_timestamp())::bigint THEN
        RETURN NULL;
    END IF;

    RETURN org_text::uuid;
END
$$;

GRANT EXECUTE ON FUNCTION tenant_security.current_org_id() TO tenant_app;
GRANT EXECUTE ON FUNCTION tenant_security.current_org_id() TO tenant_bypass;

-- 3) PG18 identifier domain: the database owns primary-key creation. id_v7 wraps uuid with a
--    DEFAULT of the PG18-native uuidv7() generator, so an insert that omits id is stamped with a
--    time-ordered UUIDv7 by the database. Application code never mints identifiers.
CREATE DOMAIN id_v7 AS uuid DEFAULT uuidv7();

-- 4) This application's tenant-scoped table, with the reference policies applied verbatim (table
--    name swapped). id is minted by the id_v7 domain default; tenant_id is stamped from the
--    verified tenant claim on insert; organization_id is stamped from the verified organization
--    claim (NULL for organization-unscoped sessions); ordinary reads and writes are scoped by the
--    verified claims; system-ops reads are unlocked by membership in tenant_bypass, not by a
--    self-settable session variable. owner_subject feeds the fine-grained authorization layer's
--    resource-owner check; it is business data here, not an isolation dimension.
CREATE TABLE document (
    id              id_v7 PRIMARY KEY,
    tenant_id       uuid NOT NULL DEFAULT tenant_security.current_tenant_id(),
    organization_id uuid DEFAULT tenant_security.current_org_id(),
    owner_subject   text NOT NULL,
    title           text NOT NULL,
    body            text NOT NULL
);

ALTER TABLE document ENABLE ROW LEVEL SECURITY;
ALTER TABLE document FORCE ROW LEVEL SECURITY;

CREATE POLICY p_tenant_isolation ON document
    FOR ALL TO public
    USING (
        pg_has_role(current_user, 'tenant_bypass', 'USAGE')
        OR tenant_id = tenant_security.current_tenant_id()
    )
    WITH CHECK (
        tenant_id = tenant_security.current_tenant_id()
    );

-- RESTRICTIVE organization cap, AND-combined with the permissive tenant policy above: the tenant
-- boundary must pass first, then this cap scopes rows within the tenant. An organization-unscoped
-- session (no verified app.org_claim) sees the whole tenant — organization scope subdivides a
-- tenant, it does not replace tenant isolation. An organization-bound session sees only its own
-- organization's rows; rows with no organization stay visible only to organization-unscoped
-- sessions and bypass readers. WITH CHECK pins writes the same way, so an organization-bound
-- session cannot write another organization's rows (organization_id is stamped by column default
-- from the same verified claim).
--
-- The cap applies only to the session's OWN tenant (the tenant-mismatch escape below): the
-- organization dimension is an intra-tenant concept, so a foreign-tenant row — reachable at all
-- only through tenant_bypass membership or an explicit read entitlement from the reference DDL —
-- is not filtered by the reader's own organization binding. The escape cannot widen writes: every
-- write must still pass the permissive p_tenant_isolation WITH CHECK, which pins rows to the
-- verified own-tenant claim.
CREATE POLICY p_organization_scope ON document
    AS RESTRICTIVE
    FOR ALL TO public
    USING (
        pg_has_role(current_user, 'tenant_bypass', 'USAGE')
        OR tenant_id IS DISTINCT FROM tenant_security.current_tenant_id()
        OR tenant_security.current_org_id() IS NULL
        OR organization_id = tenant_security.current_org_id()
    )
    WITH CHECK (
        tenant_security.current_org_id() IS NULL
        OR organization_id = tenant_security.current_org_id()
    );

-- Ordinary tenant code may read and delete rows that RLS exposes, but it may write only mutable
-- business columns. id and tenant_id are database-owned: id is minted by the id_v7 domain default,
-- and tenant_id is stamped from the verified session claim.
GRANT SELECT, DELETE ON document TO tenant_app;
GRANT INSERT (owner_subject, title, body), UPDATE (title, body) ON document TO tenant_app;
GRANT SELECT ON document TO tenant_bypass;
