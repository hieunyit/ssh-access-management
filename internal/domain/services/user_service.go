package services

import (
	"context"
	"ssh-access-management/internal/domain/entities"
	"ssh-access-management/internal/domain/repositories"
)

// UserService defines user service interface
type UserService interface {
	// User management
	CreateUser(ctx context.Context, req CreateUserRequest) (*entities.User, error)
	GetUser(ctx context.Context, id uint) (*entities.User, error)
	GetUserByUsername(ctx context.Context, username string) (*entities.User, error)
	GetUserByEmail(ctx context.Context, email string) (*entities.User, error)
	UpdateUser(ctx context.Context, id uint, req UpdateUserRequest) (*entities.User, error)
	DeleteUser(ctx context.Context, id uint) error
	ListUsers(ctx context.Context, req ListUsersRequest) (*ListUsersResponse, error)

	// User status management
	ActivateUser(ctx context.Context, id uint) error
	DeactivateUser(ctx context.Context, id uint) error
	BanUser(ctx context.Context, id uint, reason string) error

	// Authentication
	AuthenticateUser(ctx context.Context, username, password string) (*entities.User, error)
	ChangePassword(ctx context.Context, userID uint, oldPassword, newPassword string) error
	ResetPassword(ctx context.Context, email string) error
	ValidatePassword(password string) error

	// User profile
	UpdateProfile(ctx context.Context, userID uint, req UpdateProfileRequest) (*entities.User, error)
	GetUserProfile(ctx context.Context, userID uint) (*UserProfile, error)

	// SSH key management
	AddSSHKey(ctx context.Context, userID uint, req AddSSHKeyRequest) (*entities.SSHKey, error)
	GetUserSSHKeys(ctx context.Context, userID uint) ([]entities.SSHKey, error)
	UpdateSSHKey(ctx context.Context, keyID uint, req UpdateSSHKeyRequest) (*entities.SSHKey, error)
	DeleteSSHKey(ctx context.Context, keyID uint) error
	ValidateSSHKey(publicKey string) (*SSHKeyInfo, error)

	// Group and project management
	AddUserToGroup(ctx context.Context, userID, groupID uint) error
	RemoveUserFromGroup(ctx context.Context, userID, groupID uint) error
	AddUserToProject(ctx context.Context, userID, projectID uint) error
	RemoveUserFromProject(ctx context.Context, userID, projectID uint) error
	GetUserGroups(ctx context.Context, userID uint) ([]entities.Group, error)
	GetUserProjects(ctx context.Context, userID uint) ([]entities.Project, error)

	// User statistics and analytics
	GetUserStats(ctx context.Context, userID uint) (*repositories.UserStats, error)
	GetUserActivity(ctx context.Context, userID uint, days int) (*UserActivity, error)
	GetUserAccessHistory(ctx context.Context, userID uint, req AccessHistoryRequest) (*AccessHistoryResponse, error)

	// Bulk operations
	BulkCreateUsers(ctx context.Context, req BulkCreateUsersRequest) (*BulkOperationResult, error)
	BulkUpdateUsers(ctx context.Context, req BulkUpdateUsersRequest) (*BulkOperationResult, error)
	BulkDeleteUsers(ctx context.Context, userIDs []uint) (*BulkOperationResult, error)
	ImportUsersFromCSV(ctx context.Context, csvData []byte) (*ImportResult, error)
	ExportUsersToCSV(ctx context.Context, filter repositories.UserFilter) ([]byte, error)

	// User search and discovery
	SearchUsers(ctx context.Context, query string, filters UserSearchFilters) ([]entities.User, error)
	GetUsersByRole(ctx context.Context, role string) ([]entities.User, error)
	GetActiveUsers(ctx context.Context) ([]entities.User, error)
	GetInactiveUsers(ctx context.Context, days int) ([]entities.User, error)

	// Session management
	CreateUserSession(ctx context.Context, userID uint, sessionInfo SessionInfo) (*UserSession, error)
	GetUserActiveSessions(ctx context.Context, userID uint) ([]UserSession, error)
	InvalidateUserSession(ctx context.Context, sessionID string) error
	InvalidateAllUserSessions(ctx context.Context, userID uint) error
}

// Request/Response DTOs

type CreateUserRequest struct {
	Username   string `json:"username" validate:"required,min=3,max=50"`
	Email      string `json:"email" validate:"required,email"`
	FullName   string `json:"full_name" validate:"required,min=1,max=255"`
	Password   string `json:"password" validate:"required,min=8"`
	Department string `json:"department,omitempty"`
	Role       string `json:"role" validate:"required,oneof=admin user readonly"`
}

type UpdateUserRequest struct {
	Email      *string `json:"email,omitempty" validate:"omitempty,email"`
	FullName   *string `json:"full_name,omitempty" validate:"omitempty,min=1,max=255"`
	Department *string `json:"department,omitempty"`
	Role       *string `json:"role,omitempty" validate:"omitempty,oneof=admin user readonly"`
	Status     *string `json:"status,omitempty" validate:"omitempty,oneof=active inactive banned"`
}

type UpdateProfileRequest struct {
	FullName   *string `json:"full_name,omitempty" validate:"omitempty,min=1,max=255"`
	Email      *string `json:"email,omitempty" validate:"omitempty,email"`
	Department *string `json:"department,omitempty"`
}

type ListUsersRequest struct {
	Username   string `json:"username,omitempty"`
	Email      string `json:"email,omitempty"`
	FullName   string `json:"full_name,omitempty"`
	Department string `json:"department,omitempty"`
	Role       string `json:"role,omitempty"`
	Status     string `json:"status,omitempty"`
	Search     string `json:"search,omitempty"`
	GroupID    *uint  `json:"group_id,omitempty"`
	ProjectID  *uint  `json:"project_id,omitempty"`
	Page       int    `json:"page,omitempty"`
	PageSize   int    `json:"page_size,omitempty"`
	SortBy     string `json:"sort_by,omitempty"`
	SortOrder  string `json:"sort_order,omitempty"`
}

type ListUsersResponse struct {
	Users      []entities.User                `json:"users"`
	Pagination *repositories.PaginationResult `json:"pagination"`
}

type AddSSHKeyRequest struct {
	Name      string `json:"name" validate:"required,min=1,max=100"`
	PublicKey string `json:"public_key" validate:"required"`
	Comment   string `json:"comment,omitempty"`
}

type UpdateSSHKeyRequest struct {
	Name     *string `json:"name,omitempty" validate:"omitempty,min=1,max=100"`
	Comment  *string `json:"comment,omitempty"`
	IsActive *bool   `json:"is_active,omitempty"`
}

type BulkCreateUsersRequest struct {
	Users []CreateUserRequest `json:"users" validate:"required,min=1,max=100"`
}

type BulkUpdateUsersRequest struct {
	Updates []UserUpdateItem `json:"updates" validate:"required,min=1,max=100"`
}

type UserUpdateItem struct {
	ID   uint              `json:"id" validate:"required"`
	Data UpdateUserRequest `json:"data"`
}

type BulkOperationResult struct {
	TotalRequested int                  `json:"total_requested"`
	Successful     int                  `json:"successful"`
	Failed         int                  `json:"failed"`
	Errors         []BulkOperationError `json:"errors,omitempty"`
	Results        []interface{}        `json:"results,omitempty"`
}

type BulkOperationError struct {
	Index   int    `json:"index"`
	ID      *uint  `json:"id,omitempty"`
	Message string `json:"message"`
}

type ImportResult struct {
	TotalRows    int             `json:"total_rows"`
	Successful   int             `json:"successful"`
	Failed       int             `json:"failed"`
	Skipped      int             `json:"skipped"`
	Errors       []ImportError   `json:"errors,omitempty"`
	CreatedUsers []entities.User `json:"created_users,omitempty"`
}

type ImportError struct {
	Row     int    `json:"row"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

type UserSearchFilters struct {
	Role       string `json:"role,omitempty"`
	Status     string `json:"status,omitempty"`
	Department string `json:"department,omitempty"`
	HasSSHKeys *bool  `json:"has_ssh_keys,omitempty"`
	InGroup    *uint  `json:"in_group,omitempty"`
	InProject  *uint  `json:"in_project,omitempty"`
}

type UserProfile struct {
	User           *entities.User          `json:"user"`
	Stats          *repositories.UserStats `json:"stats"`
	Groups         []entities.Group        `json:"groups"`
	Projects       []entities.Project      `json:"projects"`
	SSHKeys        []entities.SSHKey       `json:"ssh_keys"`
	RecentActivity []repositories.Activity `json:"recent_activity"`
	Permissions    []string                `json:"permissions"`
}

type UserActivity struct {
	UserID           uint                    `json:"user_id"`
	Username         string                  `json:"username"`
	TimeRange        repositories.TimeRange  `json:"time_range"`
	TotalActions     int64                   `json:"total_actions"`
	ServerAccess     int64                   `json:"server_access"`
	CommandsExecuted int64                   `json:"commands_executed"`
	DataTransferred  int64                   `json:"data_transferred"`
	FailedAttempts   int64                   `json:"failed_attempts"`
	ActivityByDay    []DailyActivity         `json:"activity_by_day"`
	TopServers       []ServerAccessSummary   `json:"top_servers"`
	RecentActions    []repositories.Activity `json:"recent_actions"`
}

type DailyActivity struct {
	Date            string `json:"date"`
	Actions         int64  `json:"actions"`
	ServerAccess    int64  `json:"server_access"`
	Commands        int64  `json:"commands"`
	DataTransferred int64  `json:"data_transferred"`
}

type ServerAccessSummary struct {
	ServerID    uint   `json:"server_id"`
	ServerName  string `json:"server_name"`
	AccessCount int64  `json:"access_count"`
	LastAccess  string `json:"last_access"`
}

type AccessHistoryRequest struct {
	ServerID  *uint  `json:"server_id,omitempty"`
	StartDate string `json:"start_date,omitempty"`
	EndDate   string `json:"end_date,omitempty"`
	Page      int    `json:"page,omitempty"`
	PageSize  int    `json:"page_size,omitempty"`
}

type AccessHistoryResponse struct {
	History    []AccessHistoryItem            `json:"history"`
	Pagination *repositories.PaginationResult `json:"pagination"`
}

type AccessHistoryItem struct {
	ServerID     uint   `json:"server_id"`
	ServerName   string `json:"server_name"`
	ServerIP     string `json:"server_ip"`
	AccessTime   string `json:"access_time"`
	Duration     *int64 `json:"duration,omitempty"`
	IPAddress    string `json:"ip_address"`
	SessionID    string `json:"session_id"`
	Commands     int    `json:"commands"`
	Status       string `json:"status"`
	ErrorMessage string `json:"error_message,omitempty"`
}

type SSHKeyInfo struct {
	KeyType     string   `json:"key_type"`
	BitLength   int      `json:"bit_length"`
	Fingerprint string   `json:"fingerprint"`
	Comment     string   `json:"comment"`
	IsValid     bool     `json:"is_valid"`
	IsSecure    bool     `json:"is_secure"`
	Warnings    []string `json:"warnings,omitempty"`
}

type SessionInfo struct {
	IPAddress  string            `json:"ip_address"`
	UserAgent  string            `json:"user_agent"`
	Platform   string            `json:"platform"`
	Location   string            `json:"location,omitempty"`
	DeviceInfo map[string]string `json:"device_info,omitempty"`
}

type UserSession struct {
	ID           string            `json:"id"`
	UserID       uint              `json:"user_id"`
	IPAddress    string            `json:"ip_address"`
	UserAgent    string            `json:"user_agent"`
	Platform     string            `json:"platform"`
	Location     string            `json:"location"`
	CreatedAt    string            `json:"created_at"`
	LastActivity string            `json:"last_activity"`
	ExpiresAt    string            `json:"expires_at"`
	IsActive     bool              `json:"is_active"`
	DeviceInfo   map[string]string `json:"device_info"`
}
