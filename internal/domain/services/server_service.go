package services

import (
	"context"
	"ssh-access-management/internal/domain/entities"
	"ssh-access-management/internal/domain/repositories"
)

// ServerService defines server service interface
type ServerService interface {
	// Server management
	CreateServer(ctx context.Context, req CreateServerRequest) (*entities.Server, error)
	GetServer(ctx context.Context, id uint) (*entities.Server, error)
	GetServerByName(ctx context.Context, name string) (*entities.Server, error)
	GetServerByIP(ctx context.Context, ip string) (*entities.Server, error)
	UpdateServer(ctx context.Context, id uint, req UpdateServerRequest) (*entities.Server, error)
	DeleteServer(ctx context.Context, id uint) error
	ListServers(ctx context.Context, req ListServersRequest) (*ListServersResponse, error)

	// Server status management
	ActivateServer(ctx context.Context, id uint) error
	DeactivateServer(ctx context.Context, id uint) error
	BanServer(ctx context.Context, id uint, reason string) error
	UpdateServerStatus(ctx context.Context, id uint, status entities.ServerStatus) error

	// Server connectivity and health
	TestServerConnectivity(ctx context.Context, id uint) (*repositories.ServerConnectivity, error)
	PerformHealthCheck(ctx context.Context, id uint) (*repositories.ServerHealthCheck, error)
	UpdateServerMetrics(ctx context.Context, id uint, metrics repositories.ServerMetrics) error
	GetServerMetrics(ctx context.Context, id uint, days int) ([]repositories.ServerMetrics, error)

	// Tag management
	AddServerTags(ctx context.Context, serverID uint, tags []string) error
	RemoveServerTags(ctx context.Context, serverID uint, tags []string) error
	ReplaceServerTags(ctx context.Context, serverID uint, tags []string) error
	GetServersByTag(ctx context.Context, tag string) ([]entities.Server, error)
	GetAllTags(ctx context.Context) ([]TagInfo, error)

	// Group and project management
	AddServerToGroup(ctx context.Context, serverID, groupID uint) error
	RemoveServerFromGroup(ctx context.Context, serverID, groupID uint) error
	AddServerToProject(ctx context.Context, serverID, projectID uint) error
	RemoveServerFromProject(ctx context.Context, serverID, projectID uint) error
	GetServerGroups(ctx context.Context, serverID uint) ([]entities.Group, error)
	GetServerProjects(ctx context.Context, serverID uint) ([]entities.Project, error)

	// Server access management
	GetServerAccess(ctx context.Context, serverID uint) ([]entities.AccessGrant, error)
	GetActiveServerAccess(ctx context.Context, serverID uint) ([]entities.AccessGrant, error)
	GetServerUsers(ctx context.Context, serverID uint) ([]ServerUserInfo, error)
	GetServerSessions(ctx context.Context, serverID uint) ([]repositories.AccessSession, error)

	// Server filtering and search
	GetServersByEnvironment(ctx context.Context, environment string) ([]entities.Server, error)
	GetServersByPlatform(ctx context.Context, platform entities.Platform) ([]entities.Server, error)
	GetServersByOS(ctx context.Context, os string) ([]entities.Server, error)
	GetServersByRegion(ctx context.Context, region string) ([]entities.Server, error)
	SearchServers(ctx context.Context, query string, filters ServerSearchFilters) ([]entities.Server, error)

	// Statistics and analytics
	GetServerStats(ctx context.Context, serverID uint) (*repositories.ServerStats, error)
	GetServerActivity(ctx context.Context, serverID uint, days int) (*ServerActivity, error)
	GetPlatformSummary(ctx context.Context) ([]repositories.PlatformSummary, error)
	GetEnvironmentSummary(ctx context.Context) ([]repositories.EnvironmentSummary, error)
	GetServerDistribution(ctx context.Context) (*ServerDistribution, error)

	// Bulk operations
	BulkCreateServers(ctx context.Context, req BulkCreateServersRequest) (*BulkOperationResult, error)
	BulkUpdateServers(ctx context.Context, req BulkUpdateServersRequest) (*BulkOperationResult, error)
	BulkDeleteServers(ctx context.Context, serverIDs []uint) (*BulkOperationResult, error)
	BulkUpdateServerTags(ctx context.Context, serverIDs []uint, tags []string, action string) (*BulkOperationResult, error)
	BulkUpdateServerStatus(ctx context.Context, serverIDs []uint, status entities.ServerStatus) (*BulkOperationResult, error)

	// Import/Export
	ImportServersFromCSV(ctx context.Context, csvData []byte) (*ImportResult, error)
	ExportServersToCSV(ctx context.Context, filter repositories.ServerFilter) ([]byte, error)

	// Platform-specific operations
	SyncAWSServers(ctx context.Context, region string) (*SyncResult, error)
	SyncAzureServers(ctx context.Context, subscriptionID string) (*SyncResult, error)
	SyncVSphereServers(ctx context.Context, datacenter string) (*SyncResult, error)

	// Server automation
	ExecuteCommand(ctx context.Context, serverID uint, command string, userID uint) (*CommandResult, error)
	DeploySSHKeys(ctx context.Context, serverID uint, userIDs []uint) (*DeploymentResult, error)
	RemoveSSHKeys(ctx context.Context, serverID uint, userIDs []uint) (*DeploymentResult, error)
	UpdateServerConfiguration(ctx context.Context, serverID uint, config ServerConfig) error
}

// Request/Response DTOs

type CreateServerRequest struct {
	Name        string            `json:"name" validate:"required,min=1,max=100"`
	IP          string            `json:"ip" validate:"required,ip"`
	Hostname    string            `json:"hostname,omitempty"`
	Description string            `json:"description,omitempty"`
	Environment string            `json:"environment" validate:"required,oneof=production staging dev test"`
	Platform    entities.Platform `json:"platform" validate:"required,oneof=vsphere aws azure"`
	OS          string            `json:"os" validate:"required"`
	OSVersion   string            `json:"os_version,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	SSHPort     int               `json:"ssh_port,omitempty"`
	SSHUser     string            `json:"ssh_user,omitempty"`
	Region      string            `json:"region,omitempty"`
	GroupIDs    []uint            `json:"group_ids,omitempty"`
	ProjectIDs  []uint            `json:"project_ids,omitempty"`
}

type UpdateServerRequest struct {
	Name        *string                `json:"name,omitempty" validate:"omitempty,min=1,max=100"`
	IP          *string                `json:"ip,omitempty" validate:"omitempty,ip"`
	Hostname    *string                `json:"hostname,omitempty"`
	Description *string                `json:"description,omitempty"`
	Environment *string                `json:"environment,omitempty" validate:"omitempty,oneof=production staging dev test"`
	OS          *string                `json:"os,omitempty"`
	OSVersion   *string                `json:"os_version,omitempty"`
	SSHPort     *int                   `json:"ssh_port,omitempty"`
	SSHUser     *string                `json:"ssh_user,omitempty"`
	Region      *string                `json:"region,omitempty"`
	Status      *entities.ServerStatus `json:"status,omitempty"`
}

type ListServersRequest struct {
	Name        string `json:"name,omitempty"`
	IP          string `json:"ip,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	Environment string `json:"environment,omitempty"`
	Platform    string `json:"platform,omitempty"`
	OS          string `json:"os,omitempty"`
	Status      string `json:"status,omitempty"`
	Tag         string `json:"tag,omitempty"`
	Region      string `json:"region,omitempty"`
	GroupID     *uint  `json:"group_id,omitempty"`
	ProjectID   *uint  `json:"project_id,omitempty"`
	Search      string `json:"search,omitempty"`
	IsActive    *bool  `json:"is_active,omitempty"`
	Page        int    `json:"page,omitempty"`
	PageSize    int    `json:"page_size,omitempty"`
	SortBy      string `json:"sort_by,omitempty"`
	SortOrder   string `json:"sort_order,omitempty"`
}

type ListServersResponse struct {
	Servers    []entities.Server              `json:"servers"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *ServerListSummary             `json:"summary"`
}

type ServerListSummary struct {
	Total         int64            `json:"total"`
	Active        int64            `json:"active"`
	Inactive      int64            `json:"inactive"`
	ByPlatform    map[string]int64 `json:"by_platform"`
	ByEnvironment map[string]int64 `json:"by_environment"`
	ByStatus      map[string]int64 `json:"by_status"`
}

type BulkCreateServersRequest struct {
	Servers []CreateServerRequest `json:"servers" validate:"required,min=1,max=100"`
}

type BulkUpdateServersRequest struct {
	Updates []ServerUpdateItem `json:"updates" validate:"required,min=1,max=100"`
}

type ServerUpdateItem struct {
	ID   uint                `json:"id" validate:"required"`
	Data UpdateServerRequest `json:"data"`
}

type ServerSearchFilters struct {
	Platform    string   `json:"platform,omitempty"`
	Environment string   `json:"environment,omitempty"`
	OS          string   `json:"os,omitempty"`
	Status      string   `json:"status,omitempty"`
	Region      string   `json:"region,omitempty"`
	HasTags     []string `json:"has_tags,omitempty"`
	InGroup     *uint    `json:"in_group,omitempty"`
	InProject   *uint    `json:"in_project,omitempty"`
	IsReachable *bool    `json:"is_reachable,omitempty"`
}

type TagInfo struct {
	Name        string `json:"name"`
	Usage       int64  `json:"usage"`
	Description string `json:"description,omitempty"`
	Color       string `json:"color,omitempty"`
	Category    string `json:"category,omitempty"`
}

type ServerUserInfo struct {
	UserID     uint                `json:"user_id"`
	Username   string              `json:"username"`
	FullName   string              `json:"full_name"`
	Role       entities.AccessRole `json:"role"`
	GrantType  string              `json:"grant_type"` // direct, group, project
	GrantedAt  string              `json:"granted_at"`
	ExpiresAt  *string             `json:"expires_at,omitempty"`
	LastAccess *string             `json:"last_access,omitempty"`
	IsActive   bool                `json:"is_active"`
}

type ServerActivity struct {
	ServerID         uint                         `json:"server_id"`
	ServerName       string                       `json:"server_name"`
	TimeRange        repositories.TimeRange       `json:"time_range"`
	TotalConnections int64                        `json:"total_connections"`
	UniqueUsers      int64                        `json:"unique_users"`
	CommandsExecuted int64                        `json:"commands_executed"`
	DataTransferred  int64                        `json:"data_transferred"`
	FailedAttempts   int64                        `json:"failed_attempts"`
	ActivityByDay    []DailyServerActivity        `json:"activity_by_day"`
	TopUsers         []UserAccessSummary          `json:"top_users"`
	RecentSessions   []repositories.AccessSession `json:"recent_sessions"`
	SecurityEvents   int64                        `json:"security_events"`
}

type DailyServerActivity struct {
	Date            string `json:"date"`
	Connections     int64  `json:"connections"`
	UniqueUsers     int64  `json:"unique_users"`
	Commands        int64  `json:"commands"`
	DataTransferred int64  `json:"data_transferred"`
	FailedAttempts  int64  `json:"failed_attempts"`
}

type UserAccessSummary struct {
	UserID      uint   `json:"user_id"`
	Username    string `json:"username"`
	FullName    string `json:"full_name"`
	AccessCount int64  `json:"access_count"`
	LastAccess  string `json:"last_access"`
	TotalTime   int64  `json:"total_time"`
}

type ServerDistribution struct {
	TotalServers  int64                             `json:"total_servers"`
	ByPlatform    []repositories.PlatformSummary    `json:"by_platform"`
	ByEnvironment []repositories.EnvironmentSummary `json:"by_environment"`
	ByRegion      []RegionSummary                   `json:"by_region"`
	ByOS          []OSSummary                       `json:"by_os"`
	ByStatus      []StatusSummary                   `json:"by_status"`
	GrowthTrend   []GrowthData                      `json:"growth_trend"`
}

type RegionSummary struct {
	Region     string  `json:"region"`
	Total      int64   `json:"total"`
	Active     int64   `json:"active"`
	Percentage float64 `json:"percentage"`
}

type OSSummary struct {
	OS         string  `json:"os"`
	Version    string  `json:"version"`
	Total      int64   `json:"total"`
	Percentage float64 `json:"percentage"`
}

type StatusSummary struct {
	Status     string  `json:"status"`
	Total      int64   `json:"total"`
	Percentage float64 `json:"percentage"`
}

type GrowthData struct {
	Period  string `json:"period"`
	Added   int64  `json:"added"`
	Removed int64  `json:"removed"`
	Total   int64  `json:"total"`
}

type SyncResult struct {
	Platform           string      `json:"platform"`
	Region             string      `json:"region,omitempty"`
	TotalFound         int64       `json:"total_found"`
	NewServers         int64       `json:"new_servers"`
	UpdatedServers     int64       `json:"updated_servers"`
	DeactivatedServers int64       `json:"deactivated_servers"`
	Errors             []SyncError `json:"errors,omitempty"`
	SyncedAt           string      `json:"synced_at"`
	Duration           int64       `json:"duration_ms"`
}

type SyncError struct {
	ServerID string `json:"server_id"`
	Message  string `json:"message"`
	Type     string `json:"type"`
}

type CommandResult struct {
	ServerID   uint   `json:"server_id"`
	Command    string `json:"command"`
	ExitCode   int    `json:"exit_code"`
	Output     string `json:"output"`
	Error      string `json:"error,omitempty"`
	Duration   int64  `json:"duration_ms"`
	ExecutedAt string `json:"executed_at"`
	ExecutedBy uint   `json:"executed_by"`
}

type DeploymentResult struct {
	ServerID   uint                   `json:"server_id"`
	TotalUsers int                    `json:"total_users"`
	Successful int                    `json:"successful"`
	Failed     int                    `json:"failed"`
	Results    []DeploymentUserResult `json:"results"`
	Duration   int64                  `json:"duration_ms"`
	DeployedAt string                 `json:"deployed_at"`
}

type DeploymentUserResult struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	Success  bool   `json:"success"`
	Message  string `json:"message,omitempty"`
}

type ServerConfig struct {
	SSHPort             int               `json:"ssh_port"`
	AllowPasswordAuth   bool              `json:"allow_password_auth"`
	AllowRootLogin      bool              `json:"allow_root_login"`
	MaxAuthTries        int               `json:"max_auth_tries"`
	ClientAliveInterval int               `json:"client_alive_interval"`
	ClientAliveCountMax int               `json:"client_alive_count_max"`
	PermitTunnel        bool              `json:"permit_tunnel"`
	X11Forwarding       bool              `json:"x11_forwarding"`
	AllowTcpForwarding  bool              `json:"allow_tcp_forwarding"`
	GatewayPorts        bool              `json:"gateway_ports"`
	PrintMotd           bool              `json:"print_motd"`
	Banner              string            `json:"banner,omitempty"`
	Subsystems          map[string]string `json:"subsystems,omitempty"`
	AuthorizedKeysFile  string            `json:"authorized_keys_file"`
	LogLevel            string            `json:"log_level"`
	SyslogFacility      string            `json:"syslog_facility"`
	Custom              map[string]string `json:"custom,omitempty"`
}
