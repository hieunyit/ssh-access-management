CREATE TABLE ssh_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    public_key TEXT NOT NULL,
    fingerprint VARCHAR(255) UNIQUE NOT NULL,
    key_type VARCHAR(20) NOT NULL,
    bit_length INTEGER,
    comment VARCHAR(255),
    is_active BOOLEAN DEFAULT true,
    expires_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

-- Indexes
CREATE INDEX idx_ssh_keys_user_id ON ssh_keys(user_id);
CREATE INDEX idx_ssh_keys_fingerprint ON ssh_keys(fingerprint);
CREATE INDEX idx_ssh_keys_is_active ON ssh_keys(is_active);
CREATE INDEX idx_ssh_keys_expires_at ON ssh_keys(expires_at);
CREATE INDEX idx_ssh_keys_user_active ON ssh_keys(user_id, is_active);
CREATE INDEX idx_ssh_keys_deleted_at ON ssh_keys(deleted_at);

-- +goose Down
DROP TABLE IF EXISTS ssh_keys;