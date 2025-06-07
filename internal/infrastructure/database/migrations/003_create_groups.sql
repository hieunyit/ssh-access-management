CREATE TABLE groups (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    type VARCHAR(20) NOT NULL DEFAULT 'department',
    parent_id INTEGER REFERENCES groups(id),
    permissions JSONB DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

-- Many-to-many relationship tables
CREATE TABLE user_groups (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE server_groups (
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (server_id, group_id)
);

-- Indexes
CREATE INDEX idx_groups_name ON groups(name);
CREATE INDEX idx_groups_type ON groups(type);
CREATE INDEX idx_groups_parent_id ON groups(parent_id);
CREATE INDEX idx_groups_is_active ON groups(is_active);
CREATE INDEX idx_groups_deleted_at ON groups(deleted_at);

-- +goose Down
DROP TABLE IF EXISTS server_groups;
DROP TABLE IF EXISTS user_groups;
DROP TABLE IF EXISTS groups;