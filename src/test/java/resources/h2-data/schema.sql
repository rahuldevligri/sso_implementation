CREATE TYPE IF NOT EXISTS "JSONB" AS json;

CREATE TABLE saml_sso (
    id UUID DEFAULT UUID() PRIMARY KEY,
    entity_id VARCHAR(255),
    sp_name VARCHAR(255),
    sso_binding VARCHAR(255),
    sso_url VARCHAR(255),
    slo_binding VARCHAR(255),
    slo_url VARCHAR(255),
    name_id_formats JSONB,
    signing_cert TEXT,
    private_key TEXT,
    encryption_cert TEXT,
    sp_redirect_url VARCHAR(255),
    acs_url VARCHAR(255),
    sp_entity_id VARCHAR(255),
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);