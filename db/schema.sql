CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE users (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name varchar(50) NOT NULL,
    email varchar(255) NOT NULL UNIQUE,
    password_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW()
);

CREATE TABLE organizations (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name varchar(50) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW()
);

CREATE TABLE user_org_membership (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users(id),
    org_id bigint NOT NULL REFERENCES organizations(id),
    valid_from timestamptz NOT NULL,
    valid_to timestamptz,
    created_at timestamptz NOT NULL DEFAULT NOW()

    CONSTRAINT membership_valid_dates
        CHECK (valid_to IS NULL OR valid_from < valid_to)
);

CREATE TABLE documents (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id bigint NOT NULL REFERENCES organizations(id),
    uploaded_by bigint NOT NULL REFERENCES users(id),
    filename varchar(255) NOT NULL,
    mime_type varchar(100) NOT NULL,
    filesize bigint NOT NULL,
    storage_key text NOT NULL,
    uploaded_at timestamptz NOT NULL DEFAULT NOW()
);

CREATE TABLE document_chunks (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    doc_id bigint NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    embedding vector(3), -- TODO: set size later
    content text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX one_active_membership_per_user
ON user_org_membership(user_id)
WHERE valid_to IS NULL;
