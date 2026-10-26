-- Case-insensitive uniqueness without requiring the citext extension.
CREATE TABLE users (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email text NOT NULL,
    username text NOT NULL,
    password_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    failed_login_count integer NOT NULL DEFAULT 0,
    locked_until timestamptz,
    CONSTRAINT users_failed_login_count_nonnegative
        CHECK (failed_login_count >= 0)
);

CREATE UNIQUE INDEX users_email_lower_uidx ON users (lower(email));
CREATE UNIQUE INDEX users_username_lower_uidx ON users (lower(username));

CREATE TABLE sessions (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- SHA-256 digest bytes only; never store the raw session token.
    token_hash bytea NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CONSTRAINT sessions_token_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT sessions_expiration_after_creation CHECK (expires_at > created_at)
);

-- The token_hash UNIQUE constraint already creates its lookup index.
CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);
