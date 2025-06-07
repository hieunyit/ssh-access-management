package dto

import (
	"ssh-access-management/internal/domain/entities"
	"ssh-access-management/internal/domain/repositories"
)

// CreateServerRequest represents request to create server
type CreateServerRequest struct {
	Name        string            `json:"name" validate:"required,min=1,max=100"`
	IP          string            `json:"ip" validate:"required,ip"`
	Hostname    string            `json:"hostname,omitempty"`
	Description string            `json:"description,omitempty"`
	Environment string            `json:"environment" validate:"required,environment"`
	Platform    entities.Platform `json:"platform" validate:"required,platform"`
	OS          string            `json:"os" validate:"required"`
	OSVersion   string            `json:"os_version,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	SSHPort     int               `json:"ssh_port,omitempty" validate:"omitempty,min=1,max=65535"`
	SSHUser     string            `json:"ssh_user,omitempty"`
	Region      string            `json:"region,omitempty"`
	GroupIDs    []uint            `json:"group_ids,omitempty"`
	ProjectIDs  []uint            `json:"project_ids,omitempty"`
}

// UpdateServerRequest represents request to update server
type UpdateServerRequest struct {
	Name        *string                `json:"name,omitempty" validate:"omitempty,min=1,max=100"`
	IP          *string                `json:"ip,omitempty" validate:"omitempty,ip"`
	Hostname    *string                `json:"hostname,omitempty"`
	Description *string                `json:"description,omitempty"`
	Environment *string                `json:"environment,omitempty" validate:"omitempty,environment"`
	OS          *string                `json:"os,omitempty"`
	OSVersion   *string                `json:"os_version,omitempty"`
	SSHPort     *int                   `json:"ssh_port,omitempty" validate:"omitempty,min=1,max=65535"`
	SSHUser     *string                `json:"ssh_user,omitempty"`
	Region      *string                `json:"region,omitempty"`
	Status      *entities.ServerStatus `json:"status,omitempty" validate:"omitempty,server_status"`
}

// ListServersRequest represents request to list servers
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

// ListServersResponse represents response for listing servers
type ListServersResponse struct {
	Servers    []entities.Server              `json:"servers"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *ServersSummary                `json:"summary"`
}

// ServerDetailsResponse represents detailed server information
type ServerDetailsResponse struct {
	Server       *entities.Server                 `json:"server"`
	Groups       []ServerGroupInfo                `json:"groups"`
	Projects     []ServerProjectInfo              `json:"projects"`
	Users        []ServerUserInfo                 `json:"users"`
	AccessGrants []ServerAccessInfo               `json:"access_grants"`
	Stats        *repositories.ServerStats        `json:"stats"`
	Connectivity *repositories.ServerConnectivity `json:"connectivity,omitempty"`
	Health       *repositories.ServerHealthCheck  `json:"health,omitempty"`
	Sessions     []ServerSessionInfo              `json:"active_sessions"`
}

// ServerGroupInfo represents group information for server
type ServerGroupInfo struct {
	GroupID     uint   `json:"group_id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	IsActive    bool   `json:"is_active"`
	AddedAt     string `json:"added_at"`
}

// ServerProjectInfo represents project information for server
type ServerProjectInfo struct {
	ProjectID   uint   `json:"project_id"`
	Name        string `json:"name"`
	Code        string `json:"code"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Priority    string `json:"priority"`
	AddedAt     string `json:"added_at"`
}

// ServerUserInfo represents user access information for server
type ServerUserInfo struct {
	UserID     uint                `json:"user_id"`
	Username   string              `json:"username"`
	FullName   string              `json:"full_name"`
	Email      string              `json:"email"`
	Role       entities.AccessRole `json:"role"`
	GrantType  string              `json:"grant_type"` // direct, group, project
	GrantedAt  string              `json:"granted_at"`
	GrantedBy  string              `json:"granted_by"`
	ExpiresAt  *string             `json:"expires_at,omitempty"`
	LastAccess *string             `json:"last_access,omitempty"`
	IsActive   bool                `json:"is_active"`
}

// ServerAccessInfo represents access grant information for server
type ServerAccessInfo struct {
	GrantID     uint                `json:"grant_id"`
	UserID      *uint               `json:"user_id,omitempty"`
	GroupID     *uint               `json:"group_id,omitempty"`
	ProjectID   *uint               `json:"project_id,omitempty"`
	GranteeName string              `json:"grantee_name"`
	GranteeType string              `json:"grantee_type"`
	Role        entities.AccessRole `json:"role"`
	Status      string              `json:"status"`
	GrantedBy   string              `json:"granted_by"`
	GrantedAt   string              `json:"granted_at"`
	ExpiresAt   *string             `json:"expires_at,omitempty"`
	LastUsed    *string             `json:"last_used,omitempty"`
	UsageCount  int                 `json:"usage_count"`
}

// ServerSessionInfo represents active session information
type ServerSessionInfo struct {
	SessionID       string `json:"session_id"`
	UserID          uint   `json:"user_id"`
	Username        string `json:"username"`
	IPAddress       string `json:"ip_address"`
	StartedAt       string `json:"started_at"`
	LastActivity    string `json:"last_activity"`
	Duration        int64  `json:"duration"`
	CommandsCount   int    `json:"commands_count"`
	DataTransferred int64  `json:"data_transferred"`
	ConnectionType  string `json:"connection_type"`
}

// ServersSummary represents summary of servers
type ServersSummary struct {
	Total         int64            `json:"total"`
	Active        int64            `json:"active"`
	Inactive      int64            `json:"inactive"`
	Banned        int64            `json:"banned"`
	ByPlatform    map[string]int64 `json:"by_platform"`
	ByEnvironment map[string]int64 `json:"by_environment"`
	ByStatus      map[string]int64 `json:"by_status"`
	ByRegion      map[string]int64 `json:"by_region"`
	WithUsers     int64            `json:"with_users"`
	WithGroups    int64            `json:"with_groups"`
	WithProjects  int64            `json:"with_projects"`
}

// AddServerTagsRequest represents request to add tags to server
type AddServerTagsRequest struct {
	Tags []string `json:"tags" validate:"required,min=1"`
}

// RemoveServerTagsRequest represents request to remove tags from server
type RemoveServerTagsRequest struct {
	Tags []string `json:"tags" validate:"required,min=1"`
}

// UpdateServerTagsRequest represents request to update server tags
type UpdateServerTagsRequest struct {
	Tags   []string `json:"tags" validate:"required"`
	Action string   `json:"action" validate:"required,oneof=add remove replace"`
}

// ServerConnectivityTestRequest represents request to test server connectivity
type ServerConnectivityTestRequest struct {
	TimeoutSeconds int  `json:"timeout_seconds,omitempty" validate:"omitempty,min=1,max=300"`
	TestSSH        bool `json:"test_ssh,omitempty"`
	TestPing       bool `json:"test_ping,omitempty"`
	TestDNS        bool `json:"test_dns,omitempty"`
	CustomPort     *int `json:"custom_port,omitempty" validate:"omitempty,min=1,max=65535"`
}

// ServerSearchFilters represents server search filters
type ServerSearchFilters struct {
	Platform         string   `json:"platform,omitempty"`
	Environment      string   `json:"environment,omitempty"`
	OS               string   `json:"os,omitempty"`
	Status           string   `json:"status,omitempty"`
	Region           string   `json:"region,omitempty"`
	HasTags          []string `json:"has_tags,omitempty"`
	InGroup          *uint    `json:"in_group,omitempty"`
	InProject        *uint    `json:"in_project,omitempty"`
	IsReachable      *bool    `json:"is_reachable,omitempty"`
	MinUsers         *int     `json:"min_users,omitempty"`
	MaxUsers         *int     `json:"max_users,omitempty"`
	CreatedAfter     *string  `json:"created_after,omitempty"`
	CreatedBefore    *string  `json:"created_before,omitempty"`
	LastAccessAfter  *string  `json:"last_access_after,omitempty"`
	LastAccessBefore *string  `json:"last_access_before,omitempty"`
}

// BulkCreateServersRequest represents bulk server creation request
type BulkCreateServersRequest struct {
	Servers []CreateServerRequest `json:"servers" validate:"required,min=1,max=100"`
}

// BulkUpdateServersRequest represents bulk server update request
type BulkUpdateServersRequest struct {
	Updates []ServerUpdateItem `json:"updates" validate:"required,min=1,max=100"`
}

// ServerUpdateItem represents single server update in bulk operation
type ServerUpdateItem struct {
	ID   uint                `json:"id" validate:"required"`
	Data UpdateServerRequest `json:"data"`
}

// BulkServerOperationRequest represents bulk server operation request
type BulkServerOperationRequest struct {
	ServerIDs []uint                 `json:"server_ids" validate:"required,min=1,max=100"`
	Operation string                 `json:"operation" validate:"required,oneof=activate deactivate ban update_tags update_status"`
	Params    map[string]interface{} `json:"params,omitempty"`
}

// ServerDistributionResponse represents server distribution data
type ServerDistributionResponse struct {
	TotalServers  int64                             `json:"total_servers"`
	ByPlatform    []repositories.PlatformSummary    `json:"by_platform"`
	ByEnvironment []repositories.EnvironmentSummary `json:"by_environment"`
	ByRegion      []RegionSummary                   `json:"by_region"`
	ByOS          []OSSummary                       `json:"by_os"`
	ByStatus      []StatusSummary                   `json:"by_status"`
	GrowthTrend   []GrowthData                      `json:"growth_trend"`
	UpdatedAt     string                            `json:"updated_at"`
}

// RegionSummary represents region summary statistics
type RegionSummary struct {
	Region     string  `json:"region"`
	Total      int64   `json:"total"`
	Active     int64   `json:"active"`
	Percentage float64 `json:"percentage"`
}

// OSSummary represents OS summary statistics
type OSSummary struct {
	OS         string  `json:"os"`
	Version    string  `json:"version,omitempty"`
	Total      int64   `json:"total"`
	Percentage float64 `json:"percentage"`
}

// StatusSummary represents status summary statistics
type StatusSummary struct {
	Status     string  `json:"status"`
	Total      int64   `json:"total"`
	Percentage float64 `json:"percentage"`
}

// GrowthData represents growth trend data
type GrowthData struct {
	Period  string `json:"period"`
	Added   int64  `json:"added"`
	Removed int64  `json:"removed"`
	Total   int64  `json:"total"`
}

// TagInfo represents tag information
type TagInfo struct {
	Name        string `json:"name"`
	Usage       int64  `json:"usage"`
	Description string `json:"description,omitempty"`
	Color       string `json:"color,omitempty"`
	Category    string `json:"category,omitempty"`
}

// ServerActivity represents server activity information
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

// DailyServerActivity represents daily server activity
type DailyServerActivity struct {
	Date            string `json:"date"`
	Connections     int64  `json:"connections"`
	UniqueUsers     int64  `json:"unique_users"`
	Commands        int64  `json:"commands"`
	DataTransferred int64  `json:"data_transferred"`
	FailedAttempts  int64  `json:"failed_attempts"`
}

// UserAccessSummary represents user access summary
type UserAccessSummary struct {
	UserID      uint   `json:"user_id"`
	Username    string `json:"username"`
	FullName    string `json:"full_name"`
	AccessCount int64  `json:"access_count"`
	LastAccess  string `json:"last_access"`
	TotalTime   int64  `json:"total_time"`
}

// ServerImportRequest represents server import request
type ServerImportRequest struct {
	Data         []byte            `json:"data" validate:"required"`
	Format       string            `json:"format" validate:"required,oneof=csv json xlsx"`
	FieldMapping map[string]string `json:"field_mapping,omitempty"`
	DryRun       bool              `json:"dry_run,omitempty"`
	UpdateMode   string            `json:"update_mode" validate:"omitempty,oneof=skip update replace"`
}

// ServerExportRequest represents server export request
type ServerExportRequest struct {
	Format       string                 `json:"format" validate:"required,oneof=csv json xlsx pdf"`
	Filter       map[string]interface{} `json:"filter,omitempty"`
	Fields       []string               `json:"fields,omitempty"`
	IncludeStats bool                   `json:"include_stats,omitempty"`
	IncludeTags  bool                   `json:"include_tags,omitempty"`
	Template     string                 `json:"template,omitempty"`
}

// ServerSyncRequest represents server sync request
type ServerSyncRequest struct {
	Platform    string            `json:"platform" validate:"required,platform"`
	Region      string            `json:"region,omitempty"`
	Credentials map[string]string `json:"credentials,omitempty"`
	DryRun      bool              `json:"dry_run,omitempty"`
	SyncTags    bool              `json:"sync_tags,omitempty"`
	SyncStatus  bool              `json:"sync_status,omitempty"`
}

// ServerSyncResponse represents server sync response
type ServerSyncResponse struct {
	Platform           string        `json:"platform"`
	Region             string        `json:"region,omitempty"`
	TotalFound         int64         `json:"total_found"`
	NewServers         int64         `json:"new_servers"`
	UpdatedServers     int64         `json:"updated_servers"`
	DeactivatedServers int64         `json:"deactivated_servers"`
	SkippedServers     int64         `json:"skipped_servers"`
	Errors             []SyncError   `json:"errors,omitempty"`
	Warnings           []SyncWarning `json:"warnings,omitempty"`
	SyncedAt           string        `json:"synced_at"`
	Duration           int64         `json:"duration_ms"`
}

// SyncError represents sync error
type SyncError struct {
	ServerID    string `json:"server_id"`
	ServerName  string `json:"server_name,omitempty"`
	Message     string `json:"message"`
	Type        string `json:"type"`
	Recoverable bool   `json:"recoverable"`
}

// SyncWarning represents sync warning
type SyncWarning struct {
	ServerID   string `json:"server_id"`
	ServerName string `json:"server_name,omitempty"`
	Message    string `json:"message"`
	Type       string `json:"type"`
}

// ServerConfigRequest represents server configuration request
type ServerConfigRequest struct {
	SSHPort             *int              `json:"ssh_port,omitempty" validate:"omitempty,min=1,max=65535"`
	AllowPasswordAuth   *bool             `json:"allow_password_auth,omitempty"`
	AllowRootLogin      *bool             `json:"allow_root_login,omitempty"`
	MaxAuthTries        *int              `json:"max_auth_tries,omitempty" validate:"omitempty,min=1,max=10"`
	ClientAliveInterval *int              `json:"client_alive_interval,omitempty"`
	ClientAliveCountMax *int              `json:"client_alive_count_max,omitempty"`
	PermitTunnel        *bool             `json:"permit_tunnel,omitempty"`
	X11Forwarding       *bool             `json:"x11_forwarding,omitempty"`
	AllowTcpForwarding  *bool             `json:"allow_tcp_forwarding,omitempty"`
	GatewayPorts        *bool             `json:"gateway_ports,omitempty"`
	PrintMotd           *bool             `json:"print_motd,omitempty"`
	Banner              *string           `json:"banner,omitempty"`
	AuthorizedKeysFile  *string           `json:"authorized_keys_file,omitempty"`
	LogLevel            *string           `json:"log_level,omitempty" validate:"omitempty,oneof=QUIET FATAL ERROR INFO VERBOSE DEBUG DEBUG1 DEBUG2 DEBUG3"`
	SyslogFacility      *string           `json:"syslog_facility,omitempty"`
	Custom              map[string]string `json:"custom,omitempty"`
}

// ServerCommandRequest represents server command execution request
type ServerCommandRequest struct {
	Command     string            `json:"command" validate:"required"`
	Args        []string          `json:"args,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	WorkingDir  string            `json:"working_dir,omitempty"`
	Timeout     int               `json:"timeout,omitempty" validate:"omitempty,min=1,max=3600"`
	RunAsUser   string            `json:"run_as_user,omitempty"`
}

// ServerCommandResponse represents server command execution response
type ServerCommandResponse struct {
	Command     string            `json:"command"`
	Args        []string          `json:"args,omitempty"`
	ExitCode    int               `json:"exit_code"`
	Output      string            `json:"output"`
	Error       string            `json:"error,omitempty"`
	Duration    int64             `json:"duration_ms"`
	ExecutedAt  string            `json:"executed_at"`
	ExecutedBy  uint              `json:"executed_by"`
	Environment map[string]string `json:"environment,omitempty"`
}

// ServerDeploymentRequest represents SSH key deployment request
type ServerDeploymentRequest struct {
	UserIDs   []uint `json:"user_ids" validate:"required,min=1"`
	Operation string `json:"operation" validate:"required,oneof=deploy remove sync"`
	Force     bool   `json:"force,omitempty"`
	Backup    bool   `json:"backup,omitempty"`
}

// ServerDeploymentResponse represents SSH key deployment response
type ServerDeploymentResponse struct {
	Operation  string                 `json:"operation"`
	TotalUsers int                    `json:"total_users"`
	Successful int                    `json:"successful"`
	Failed     int                    `json:"failed"`
	Skipped    int                    `json:"skipped"`
	Results    []DeploymentUserResult `json:"results"`
	Duration   int64                  `json:"duration_ms"`
	DeployedAt string                 `json:"deployed_at"`
	BackupPath string                 `json:"backup_path,omitempty"`
}

// DeploymentUserResult represents deployment result for a user
type DeploymentUserResult struct {
	UserID    uint     `json:"user_id"`
	Username  string   `json:"username"`
	Success   bool     `json:"success"`
	Message   string   `json:"message,omitempty"`
	KeysCount int      `json:"keys_count"`
	Actions   []string `json:"actions,omitempty"`
}

// ServerMaintenanceRequest represents server maintenance request
type ServerMaintenanceRequest struct {
	Type        string                 `json:"type" validate:"required,oneof=restart reboot update patch backup"`
	Scheduled   bool                   `json:"scheduled,omitempty"`
	ScheduledAt *string                `json:"scheduled_at,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
	NotifyUsers bool                   `json:"notify_users,omitempty"`
	Reason      string                 `json:"reason,omitempty"`
}

// ServerMaintenanceResponse represents server maintenance response
type ServerMaintenanceResponse struct {
	MaintenanceID string                 `json:"maintenance_id"`
	Type          string                 `json:"type"`
	Status        string                 `json:"status"`
	StartedAt     string                 `json:"started_at"`
	CompletedAt   *string                `json:"completed_at,omitempty"`
	Duration      *int64                 `json:"duration_ms,omitempty"`
	Success       bool                   `json:"success"`
	Message       string                 `json:"message,omitempty"`
	Results       map[string]interface{} `json:"results,omitempty"`
}
