-- internal/infrastructure/database/migrations/002_create_servers.sql
-- Migration: Create servers table
-- +goose Up
CREATE TABLE servers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    ip VARCHAR(45) NOT NULL,
    hostname VARCHAR(255),
    description TEXT,
    environment VARCHAR(50) NOT NULL,
    platform VARCHAR(20) NOT NULL,
    os VARCHAR(100) NOT NULL,
    os_version VARCHAR(50),
    tags JSONB DEFAULT '[]',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    ssh_port INTEGER DEFAULT 22,
    ssh_user VARCHAR(50) DEFAULT 'root',
    region VARCHAR(50),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

-- Indexes
CREATE INDEX idx_servers_name ON servers(name);
CREATE INDEX idx_servers_ip ON servers(ip);
CREATE INDEX idx_servers_platform ON servers(platform);
CREATE INDEX idx_servers_environment ON servers(environment);
CREATE INDEX idx_servers_status ON servers(status);
CREATE INDEX idx_servers_region ON servers(region);
CREATE INDEX idx_servers_tags ON servers USING GIN(tags);
CREATE INDEX idx_servers_deleted_at ON servers(deleted_at);

-- +goose Down
DROP TABLE IF EXISTS servers;