CREATE TABLE access_grants (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    group_id INTEGER REFERENCES groups(id),
    project_id INTEGER REFERENCES projects(id),
    server_id INTEGER NOT NULL REFERENCES servers(id),
    role VARCHAR(20) NOT NULL DEFAULT 'readonly',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    reason TEXT,
    granted_by INTEGER NOT NULL REFERENCES users(id),
    granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    revoked_by INTEGER REFERENCES users(id),
    revoked_at TIMESTAMP,
    last_used_at TIMESTAMP,
    usage_count INTEGER DEFAULT 0,
    conditions JSONB DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP,
    
    -- Ensure only one grantee type per grant
    CONSTRAINT chk_single_grantee CHECK (
        (user_id IS NOT NULL)::INT + 
        (group_id IS NOT NULL)::INT + 
        (project_id IS NOT NULL)::INT = 1
    )
);

CREATE TABLE access_requests (
    id SERIAL PRIMARY KEY,
    requester_id INTEGER NOT NULL REFERENCES users(id),
    server_id INTEGER NOT NULL REFERENCES servers(id),
    role VARCHAR(20) NOT NULL,
    reason TEXT NOT NULL,
    duration INTEGER NOT NULL, -- hours
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    approved_by INTEGER REFERENCES users(id),
    approved_at TIMESTAMP,
    rejected_by INTEGER REFERENCES users(id),
    rejected_at TIMESTAMP,
    rejection_reason TEXT,
    expires_at TIMESTAMP NOT NULL,
    conditions JSONB DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

CREATE TABLE access_sessions (
    id VARCHAR(100) PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    server_id INTEGER NOT NULL REFERENCES servers(id),
    grant_id INTEGER NOT NULL REFERENCES access_grants(id),
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP,
    duration BIGINT,
    commands_count INTEGER DEFAULT 0,
    data_transferred BIGINT DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    connection_type VARCHAR(20),
    termination_reason VARCHAR(100),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for access_grants
CREATE INDEX idx_access_grants_user_id ON access_grants(user_id);
CREATE INDEX idx_access_grants_group_id ON access_grants(group_id);
CREATE INDEX idx_access_grants_project_id ON access_grants(project_id);
CREATE INDEX idx_access_grants_server_id ON access_grants(server_id);
CREATE INDEX idx_access_grants_status ON access_grants(status);
CREATE INDEX idx_access_grants_granted_by ON access_grants(granted_by);
CREATE INDEX idx_access_grants_expires_at ON access_grants(expires_at);
CREATE INDEX idx_access_grants_user_server ON access_grants(user_id, server_id);
CREATE INDEX idx_access_grants_deleted_at ON access_grants(deleted_at);

-- Indexes for access_requests
CREATE INDEX idx_access_requests_requester_id ON access_requests(requester_id);
CREATE INDEX idx_access_requests_server_id ON access_requests(server_id);
CREATE INDEX idx_access_requests_status ON access_requests(status);
CREATE INDEX idx_access_requests_approved_by ON access_requests(approved_by);
CREATE INDEX idx_access_requests_expires_at ON access_requests(expires_at);
CREATE INDEX idx_access_requests_deleted_at ON access_requests(deleted_at);

-- Indexes for access_sessions
CREATE INDEX idx_access_sessions_user_id ON access_sessions(user_id);
CREATE INDEX idx_access_sessions_server_id ON access_sessions(server_id);
CREATE INDEX idx_access_sessions_grant_id ON access_sessions(grant_id);
CREATE INDEX idx_access_sessions_is_active ON access_sessions(is_active);
CREATE INDEX idx_access_sessions_started_at ON access_sessions(started_at);

-- +goose Down
DROP TABLE IF EXISTS access_sessions;
DROP TABLE IF EXISTS access_requests;
DROP TABLE IF EXISTS access_grants;
