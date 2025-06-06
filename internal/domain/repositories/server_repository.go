package repositories

import (
	"context"
	"ssh-access-management/internal/domain/entities"
)

// ServerRepository defines server repository interface
type ServerRepository interface {
	// Server CRUD operations
	Create(ctx context.Context, server *entities.Server) error
	GetByID(ctx context.Context, id uint) (*entities.Server, error)
	GetByName(ctx context.Context, name string) (*entities.Server, error)
	GetByIP(ctx context.Context, ip string) (*entities.Server, error)
	Update(ctx context.Context, server *entities.Server) error
	Delete(ctx context.Context, id uint) error
	List(ctx context.Context, filter ServerFilter) ([]entities.Server, *PaginationResult, error)

	// Server status management
	Activate(ctx context.Context, id uint) error
	Deactivate(ctx context.Context, id uint) error
	Ban(ctx context.Context, id uint) error
	UpdateStatus(ctx context.Context, id uint, status entities.ServerStatus) error

	// Server groups and projects
	GetServerGroups(ctx context.Context, serverID uint) ([]entities.Group, error)
	GetServerProjects(ctx context.Context, serverID uint) ([]entities.Project, error)
	AddToGroup(ctx context.Context, serverID, groupID uint) error
	RemoveFromGroup(ctx context.Context, serverID, groupID uint) error
	AddToProject(ctx context.Context, serverID, projectID uint) error
	RemoveFromProject(ctx context.Context, serverID, projectID uint) error

	// Tag management
	AddTag(ctx context.Context, serverID uint, tag string) error
	RemoveTag(ctx context.Context, serverID uint, tag string) error
	AddTags(ctx context.Context, serverID uint, tags []string) error
	GetServersByTag(ctx context.Context, tag string) ([]entities.Server, error)
	GetAllTags(ctx context.Context) ([]string, error)

	// Server filtering and search
	GetByEnvironment(ctx context.Context, environment string) ([]entities.Server, error)
	GetByPlatform(ctx context.Context, platform entities.Platform) ([]entities.Server, error)
	GetByOS(ctx context.Context, os string) ([]entities.Server, error)
	GetByRegion(ctx context.Context, region string) ([]entities.Server, error)
	SearchServers(ctx context.Context, query string) ([]entities.Server, error)

	// Server access and connectivity
	GetServerAccess(ctx context.Context, serverID uint) ([]entities.AccessGrant, error)
	GetActiveServerAccess(ctx context.Context, serverID uint) ([]entities.AccessGrant, error)
	CheckServerConnectivity(ctx context.Context, serverID uint) (*ServerConnectivity, error)
	UpdateConnectivityStatus(ctx context.Context, serverID uint, status bool) error

	// Server statistics
	GetServerStats(ctx context.Context, serverID uint) (*ServerStats, error)
	GetServersByStatus(ctx context.Context, status entities.ServerStatus) ([]entities.Server, error)
	GetServersCount(ctx context.Context) (int64, error)
	GetActiveServersCount(ctx context.Context) (int64, error)

	// Platform-specific operations
	GetPlatformSummary(ctx context.Context) ([]PlatformSummary, error)
	GetEnvironmentSummary(ctx context.Context) ([]EnvironmentSummary, error)

	// Bulk operations
	BulkCreate(ctx context.Context, servers []entities.Server) error
	BulkUpdate(ctx context.Context, servers []entities.Server) error
	BulkDelete(ctx context.Context, ids []uint) error
	BulkUpdateTags(ctx context.Context, serverIDs []uint, tags []string) error
	BulkUpdateStatus(ctx context.Context, serverIDs []uint, status entities.ServerStatus) error
}

// ServerFilter represents server filtering options
type ServerFilter struct {
	Name        string
	IP          string
	Hostname    string
	Environment string
	Platform    string
	OS          string
	Status      string
	Tag         string
	Region      string
	GroupID     *uint
	ProjectID   *uint
	Search      string
	IsActive    *bool
	Pagination  PaginationParams
	SortBy      string
	SortOrder   string
}

// ServerStats represents server statistics
type ServerStats struct {
	TotalConnections      int64            `json:"total_connections"`
	ActiveConnections     int64            `json:"active_connections"`
	LastAccessAt          *string          `json:"last_access_at"`
	TotalUsers            int64            `json:"total_users"`
	ActiveUsers           int64            `json:"active_users"`
	GroupsCount           int64            `json:"groups_count"`
	ProjectsCount         int64            `json:"projects_count"`
	AccessGrantsCount     int64            `json:"access_grants_count"`
	AvgSessionDuration    float64          `json:"avg_session_duration"`
	TotalDataTransfer     int64            `json:"total_data_transfer"`
	ConnectivityStatus    bool             `json:"connectivity_status"`
	LastConnectivityCheck *string          `json:"last_connectivity_check"`
	RecentActivities      []ServerActivity `json:"recent_activities"`
	ResourceUsage         *ResourceUsage   `json:"resource_usage,omitempty"`
}

// ServerActivity represents server activity
type ServerActivity struct {
	UserID    uint   `json:"user_id"`
	Username  string `json:"username"`
	Action    string `json:"action"`
	Timestamp string `json:"timestamp"`
	Duration  int64  `json:"duration"`
	IPAddress string `json:"ip_address"`
	SessionID string `json:"session_id"`
	Command   string `json:"command,omitempty"`
	ExitCode  *int   `json:"exit_code,omitempty"`
}

// ResourceUsage represents server resource usage
type ResourceUsage struct {
	CPUUsage    float64 `json:"cpu_usage"`
	MemoryUsage float64 `json:"memory_usage"`
	DiskUsage   float64 `json:"disk_usage"`
	NetworkIn   int64   `json:"network_in"`
	NetworkOut  int64   `json:"network_out"`
	Timestamp   string  `json:"timestamp"`
}

// ServerConnectivity represents server connectivity status
type ServerConnectivity struct {
	IsReachable    bool    `json:"is_reachable"`
	ResponseTime   float64 `json:"response_time_ms"`
	LastChecked    string  `json:"last_checked"`
	ErrorMessage   string  `json:"error_message,omitempty"`
	SSHPort        bool    `json:"ssh_port_open"`
	DNSResolution  bool    `json:"dns_resolution"`
	NetworkLatency float64 `json:"network_latency_ms"`
}

// PlatformSummary represents platform summary statistics
type PlatformSummary struct {
	Platform   string  `json:"platform"`
	Total      int64   `json:"total"`
	Active     int64   `json:"active"`
	Inactive   int64   `json:"inactive"`
	Banned     int64   `json:"banned"`
	Percentage float64 `json:"percentage"`
}

// EnvironmentSummary represents environment summary statistics
type EnvironmentSummary struct {
	Environment string  `json:"environment"`
	Total       int64   `json:"total"`
	Active      int64   `json:"active"`
	Inactive    int64   `json:"inactive"`
	Banned      int64   `json:"banned"`
	Percentage  float64 `json:"percentage"`
}

// ServerHealthCheck represents server health check result
type ServerHealthCheck struct {
	ServerID     uint            `json:"server_id"`
	ServerName   string          `json:"server_name"`
	IsHealthy    bool            `json:"is_healthy"`
	ResponseTime float64         `json:"response_time_ms"`
	CheckedAt    string          `json:"checked_at"`
	ErrorMessage string          `json:"error_message,omitempty"`
	Services     []ServiceStatus `json:"services"`
}

// ServiceStatus represents individual service status
type ServiceStatus struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Port      int    `json:"port"`
	IsRunning bool   `json:"is_running"`
	CheckedAt string `json:"checked_at"`
}

// ServerMetrics represents server performance metrics
type ServerMetrics struct {
	ServerID          uint    `json:"server_id"`
	Timestamp         string  `json:"timestamp"`
	CPUUsage          float64 `json:"cpu_usage"`
	MemoryUsage       float64 `json:"memory_usage"`
	DiskUsage         float64 `json:"disk_usage"`
	NetworkInbound    int64   `json:"network_inbound"`
	NetworkOutbound   int64   `json:"network_outbound"`
	ActiveConnections int     `json:"active_connections"`
	LoadAverage       float64 `json:"load_average"`
	UptimeSeconds     int64   `json:"uptime_seconds"`
}
