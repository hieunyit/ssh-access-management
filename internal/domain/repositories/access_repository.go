package repositories

import (
	"context"
	"ssh-access-management/internal/domain/entities"
	"time"
)

// AccessRepository defines access repository interface
type AccessRepository interface {
	// Access Grant CRUD operations
	CreateGrant(ctx context.Context, grant *entities.AccessGrant) error
	GetGrantByID(ctx context.Context, id uint) (*entities.AccessGrant, error)
	UpdateGrant(ctx context.Context, grant *entities.AccessGrant) error
	DeleteGrant(ctx context.Context, id uint) error
	ListGrants(ctx context.Context, filter AccessGrantFilter) ([]entities.AccessGrant, *PaginationResult, error)

	// Access Request CRUD operations
	CreateRequest(ctx context.Context, request *entities.AccessRequest) error
	GetRequestByID(ctx context.Context, id uint) (*entities.AccessRequest, error)
	UpdateRequest(ctx context.Context, request *entities.AccessRequest) error
	DeleteRequest(ctx context.Context, id uint) error
	ListRequests(ctx context.Context, filter AccessRequestFilter) ([]entities.AccessRequest, *PaginationResult, error)

	// Grant management
	GrantUserAccess(ctx context.Context, userID, serverID, grantedBy uint, role entities.AccessRole, expiresAt *time.Time, conditions entities.AccessConditions) (*entities.AccessGrant, error)
	GrantGroupAccess(ctx context.Context, groupID, serverID, grantedBy uint, role entities.AccessRole, expiresAt *time.Time, conditions entities.AccessConditions) (*entities.AccessGrant, error)
	GrantProjectAccess(ctx context.Context, projectID, serverID, grantedBy uint, role entities.AccessRole, expiresAt *time.Time, conditions entities.AccessConditions) (*entities.AccessGrant, error)
	RevokeAccess(ctx context.Context, grantID, revokedBy uint) error
	RevokeUserAccess(ctx context.Context, userID, serverID uint) error
	RevokeGroupAccess(ctx context.Context, groupID, serverID uint) error
	RevokeProjectAccess(ctx context.Context, projectID, serverID uint) error

	// Grant queries
	GetUserAccess(ctx context.Context, userID uint) ([]entities.AccessGrant, error)
	GetUserServerAccess(ctx context.Context, userID, serverID uint) (*entities.AccessGrant, error)
	GetGroupAccess(ctx context.Context, groupID uint) ([]entities.AccessGrant, error)
	GetProjectAccess(ctx context.Context, projectID uint) ([]entities.AccessGrant, error)
	GetServerAccess(ctx context.Context, serverID uint) ([]entities.AccessGrant, error)
	GetActiveGrants(ctx context.Context, serverID uint) ([]entities.AccessGrant, error)
	GetExpiredGrants(ctx context.Context) ([]entities.AccessGrant, error)
	GetExpiringGrants(ctx context.Context, beforeTime time.Time) ([]entities.AccessGrant, error)

	// User effective access (includes group and project access)
	GetUserEffectiveAccess(ctx context.Context, userID uint) ([]EffectiveAccess, error)
	GetUserEffectiveServerAccess(ctx context.Context, userID, serverID uint) (*EffectiveAccess, error)
	CheckUserServerAccess(ctx context.Context, userID, serverID uint) (bool, error)

	// Request management
	ApproveRequest(ctx context.Context, requestID, approvedBy uint) error
	RejectRequest(ctx context.Context, requestID, rejectedBy uint, reason string) error
	GetPendingRequests(ctx context.Context, approverID uint) ([]entities.AccessRequest, error)
	GetUserRequests(ctx context.Context, userID uint) ([]entities.AccessRequest, error)
	GetServerRequests(ctx context.Context, serverID uint) ([]entities.AccessRequest, error)
	GetExpiredRequests(ctx context.Context) ([]entities.AccessRequest, error)

	// Session tracking
	CreateSession(ctx context.Context, session *AccessSession) error
	GetActiveSession(ctx context.Context, userID, serverID uint) (*AccessSession, error)
	GetUserActiveSessions(ctx context.Context, userID uint) ([]AccessSession, error)
	GetServerActiveSessions(ctx context.Context, serverID uint) ([]AccessSession, error)
	UpdateSessionActivity(ctx context.Context, sessionID string, lastActivity time.Time) error
	CloseSession(ctx context.Context, sessionID string) error
	GetExpiredSessions(ctx context.Context) ([]AccessSession, error)

	// Usage tracking
	IncrementUsage(ctx context.Context, grantID uint) error
	UpdateLastUsed(ctx context.Context, grantID uint) error
	GetAccessUsageStats(ctx context.Context, grantID uint) (*AccessUsageStats, error)

	// Access statistics
	GetAccessStats(ctx context.Context) (*AccessStats, error)
	GetUserAccessStats(ctx context.Context, userID uint) (*UserAccessStats, error)
	GetServerAccessStats(ctx context.Context, serverID uint) (*ServerAccessStats, error)
	GetAccessTrends(ctx context.Context, days int) ([]AccessTrend, error)

	// Cleanup operations
	CleanupExpiredGrants(ctx context.Context) (int64, error)
	CleanupExpiredRequests(ctx context.Context) (int64, error)
	CleanupInactiveSessions(ctx context.Context, timeout time.Duration) (int64, error)

	// Bulk operations
	BulkGrantAccess(ctx context.Context, grants []entities.AccessGrant) error
	BulkRevokeAccess(ctx context.Context, grantIDs []uint, revokedBy uint) error
	BulkApproveRequests(ctx context.Context, requestIDs []uint, approvedBy uint) error
	BulkRejectRequests(ctx context.Context, requestIDs []uint, rejectedBy uint, reason string) error
}

// AccessGrantFilter represents access grant filtering options
type AccessGrantFilter struct {
	UserID        *uint
	GroupID       *uint
	ProjectID     *uint
	ServerID      *uint
	Role          string
	Status        string
	GrantedBy     *uint
	IsExpired     *bool
	IsActive      *bool
	ExpiresAfter  *time.Time
	ExpiresBefore *time.Time
	GrantedAfter  *time.Time
	GrantedBefore *time.Time
	Pagination    PaginationParams
	SortBy        string
	SortOrder     string
}

// AccessRequestFilter represents access request filtering options
type AccessRequestFilter struct {
	RequesterID   *uint
	ServerID      *uint
	Role          string
	Status        string
	ApprovedBy    *uint
	RejectedBy    *uint
	CreatedAfter  *time.Time
	CreatedBefore *time.Time
	Pagination    PaginationParams
	SortBy        string
	SortOrder     string
}

// EffectiveAccess represents user's effective access including inherited access
type EffectiveAccess struct {
	ServerID      uint                      `json:"server_id"`
	ServerName    string                    `json:"server_name"`
	ServerIP      string                    `json:"server_ip"`
	HighestRole   entities.AccessRole       `json:"highest_role"`
	DirectAccess  *entities.AccessGrant     `json:"direct_access,omitempty"`
	GroupAccess   []entities.AccessGrant    `json:"group_access,omitempty"`
	ProjectAccess []entities.AccessGrant    `json:"project_access,omitempty"`
	IsActive      bool                      `json:"is_active"`
	ExpiresAt     *time.Time                `json:"expires_at,omitempty"`
	Conditions    entities.AccessConditions `json:"conditions"`
	InheritedFrom []AccessInheritance       `json:"inherited_from"`
}

// AccessInheritance represents access inheritance information
type AccessInheritance struct {
	Type string              `json:"type"` // "group" or "project"
	ID   uint                `json:"id"`
	Name string              `json:"name"`
	Role entities.AccessRole `json:"role"`
}

// AccessSession represents an active access session
type AccessSession struct {
	ID                string               `json:"id" gorm:"primaryKey;size:100"`
	UserID            uint                 `json:"user_id" gorm:"not null;index"`
	ServerID          uint                 `json:"server_id" gorm:"not null;index"`
	GrantID           uint                 `json:"grant_id" gorm:"not null;index"`
	IPAddress         string               `json:"ip_address" gorm:"size:45"`
	UserAgent         string               `json:"user_agent" gorm:"size:500"`
	StartedAt         time.Time            `json:"started_at" gorm:"not null"`
	LastActivity      time.Time            `json:"last_activity" gorm:"not null"`
	EndedAt           *time.Time           `json:"ended_at"`
	Duration          *int64               `json:"duration"` // Duration in seconds
	CommandsCount     int                  `json:"commands_count" gorm:"default:0"`
	DataTransferred   int64                `json:"data_transferred" gorm:"default:0"` // Bytes
	IsActive          bool                 `json:"is_active" gorm:"default:true"`
	ConnectionType    string               `json:"connection_type" gorm:"size:20"` // ssh, scp, sftp
	TerminationReason string               `json:"termination_reason" gorm:"size:100"`
	User              entities.User        `json:"user" gorm:"foreignKey:UserID"`
	Server            entities.Server      `json:"server" gorm:"foreignKey:ServerID"`
	Grant             entities.AccessGrant `json:"grant" gorm:"foreignKey:GrantID"`
	CreatedAt         time.Time            `json:"created_at"`
	UpdatedAt         time.Time            `json:"updated_at"`
}

// AccessUsageStats represents access usage statistics
type AccessUsageStats struct {
	GrantID            uint         `json:"grant_id"`
	TotalUsages        int64        `json:"total_usages"`
	LastUsedAt         *time.Time   `json:"last_used_at"`
	TotalSessionTime   int64        `json:"total_session_time"`   // Total time in seconds
	AverageSessionTime float64      `json:"average_session_time"` // Average time in seconds
	CommandsExecuted   int64        `json:"commands_executed"`
	DataTransferred    int64        `json:"data_transferred"` // Total bytes
	UniqueIPsUsed      int64        `json:"unique_ips_used"`
	FirstUsedAt        *time.Time   `json:"first_used_at"`
	UsageByDay         []DailyUsage `json:"usage_by_day"`
}

// DailyUsage represents daily usage statistics
type DailyUsage struct {
	Date         string `json:"date"`
	Sessions     int64  `json:"sessions"`
	Duration     int64  `json:"duration"`
	Commands     int64  `json:"commands"`
	DataTransfer int64  `json:"data_transfer"`
}

// AccessStats represents overall access statistics
type AccessStats struct {
	TotalGrants            int64   `json:"total_grants"`
	ActiveGrants           int64   `json:"active_grants"`
	ExpiredGrants          int64   `json:"expired_grants"`
	RevokedGrants          int64   `json:"revoked_grants"`
	TotalRequests          int64   `json:"total_requests"`
	PendingRequests        int64   `json:"pending_requests"`
	ApprovedRequests       int64   `json:"approved_requests"`
	RejectedRequests       int64   `json:"rejected_requests"`
	ActiveSessions         int64   `json:"active_sessions"`
	TotalSessions          int64   `json:"total_sessions"`
	AverageSessionDuration float64 `json:"average_session_duration"`
	TotalDataTransferred   int64   `json:"total_data_transferred"`
}

// UserAccessStats represents user-specific access statistics
type UserAccessStats struct {
	UserID             uint              `json:"user_id"`
	TotalGrants        int64             `json:"total_grants"`
	ActiveGrants       int64             `json:"active_grants"`
	ServersAccessible  int64             `json:"servers_accessible"`
	TotalSessions      int64             `json:"total_sessions"`
	ActiveSessions     int64             `json:"active_sessions"`
	LastAccessAt       *time.Time        `json:"last_access_at"`
	TotalSessionTime   int64             `json:"total_session_time"`
	CommandsExecuted   int64             `json:"commands_executed"`
	DataTransferred    int64             `json:"data_transferred"`
	MostAccessedServer *ServerAccessInfo `json:"most_accessed_server"`
}

// ServerAccessStats represents server-specific access statistics
type ServerAccessStats struct {
	ServerID         uint            `json:"server_id"`
	TotalGrants      int64           `json:"total_grants"`
	ActiveGrants     int64           `json:"active_grants"`
	UsersWithAccess  int64           `json:"users_with_access"`
	TotalSessions    int64           `json:"total_sessions"`
	ActiveSessions   int64           `json:"active_sessions"`
	LastAccessAt     *time.Time      `json:"last_access_at"`
	TotalSessionTime int64           `json:"total_session_time"`
	CommandsExecuted int64           `json:"commands_executed"`
	DataTransferred  int64           `json:"data_transferred"`
	MostActiveUser   *UserAccessInfo `json:"most_active_user"`
}

// ServerAccessInfo represents server access information
type ServerAccessInfo struct {
	ServerID    uint       `json:"server_id"`
	ServerName  string     `json:"server_name"`
	AccessCount int64      `json:"access_count"`
	LastAccess  *time.Time `json:"last_access"`
}

// UserAccessInfo represents user access information
type UserAccessInfo struct {
	UserID      uint       `json:"user_id"`
	Username    string     `json:"username"`
	AccessCount int64      `json:"access_count"`
	LastAccess  *time.Time `json:"last_access"`
}

// AccessTrend represents access trend data
type AccessTrend struct {
	Date             string `json:"date"`
	NewGrants        int64  `json:"new_grants"`
	RevokedGrants    int64  `json:"revoked_grants"`
	NewRequests      int64  `json:"new_requests"`
	ApprovedRequests int64  `json:"approved_requests"`
	RejectedRequests int64  `json:"rejected_requests"`
	ActiveSessions   int64  `json:"active_sessions"`
	TotalSessions    int64  `json:"total_sessions"`
}

// TableName sets the table name for AccessSession
func (AccessSession) TableName() string {
	return "access_sessions"
}
