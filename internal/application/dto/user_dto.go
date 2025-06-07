package dto

import (
	"ssh-access-management/internal/domain/entities"
	"ssh-access-management/internal/domain/repositories"
	"time"
)

// CreateUserRequest represents request to create user
type CreateUserRequest struct {
	Username   string `json:"username" validate:"required,min=3,max=50,alphanum"`
	Email      string `json:"email" validate:"required,email"`
	FullName   string `json:"full_name" validate:"required,min=1,max=255"`
	Password   string `json:"password" validate:"required,min=8"`
	Department string `json:"department,omitempty" validate:"omitempty,max=100"`
	Role       string `json:"role" validate:"required,oneof=admin user readonly"`
	GroupIDs   []uint `json:"group_ids,omitempty"`
	ProjectIDs []uint `json:"project_ids,omitempty"`
}

// UpdateUserRequest represents request to update user
type UpdateUserRequest struct {
	Email      *string `json:"email,omitempty" validate:"omitempty,email"`
	FullName   *string `json:"full_name,omitempty" validate:"omitempty,min=1,max=255"`
	Department *string `json:"department,omitempty" validate:"omitempty,max=100"`
	Role       *string `json:"role,omitempty" validate:"omitempty,oneof=admin user readonly"`
	Status     *string `json:"status,omitempty" validate:"omitempty,oneof=active inactive banned"`
	IsActive   *bool   `json:"is_active,omitempty"`
}

// ListUsersRequest represents request to list users
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
	IsActive   *bool  `json:"is_active,omitempty"`
	HasSSHKeys *bool  `json:"has_ssh_keys,omitempty"`
	Page       int    `json:"page,omitempty"`
	PageSize   int    `json:"page_size,omitempty"`
	SortBy     string `json:"sort_by,omitempty"`
	SortOrder  string `json:"sort_order,omitempty"`
}

// ListUsersResponse represents response for listing users
type ListUsersResponse struct {
	Users      []entities.User                `json:"users"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *UsersSummary                  `json:"summary"`
}

// UserDetailsResponse represents detailed user information
type UserDetailsResponse struct {
	User           *entities.User          `json:"user"`
	Groups         []UserGroupInfo         `json:"groups"`
	Projects       []UserProjectInfo       `json:"projects"`
	SSHKeys        []entities.SSHKey       `json:"ssh_keys"`
	AccessGrants   []UserAccessInfo        `json:"access_grants"`
	Stats          *repositories.UserStats `json:"stats"`
	RecentActivity []repositories.Activity `json:"recent_activity"`
	Sessions       []UserSessionInfo       `json:"active_sessions"`
	Permissions    []string                `json:"permissions"`
}

// UserGroupInfo represents group information for user
type UserGroupInfo struct {
	GroupID     uint   `json:"group_id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	IsActive    bool   `json:"is_active"`
	JoinedAt    string `json:"joined_at"`
	Role        string `json:"role"`
}

// UserProjectInfo represents project information for user
type UserProjectInfo struct {
	ProjectID   uint   `json:"project_id"`
	Name        string `json:"name"`
	Code        string `json:"code"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Priority    string `json:"priority"`
	Role        string `json:"role"`
	JoinedAt    string `json:"joined_at"`
}

// UserAccessInfo represents access grant information for user
type UserAccessInfo struct {
	GrantID       uint                      `json:"grant_id"`
	ServerID      uint                      `json:"server_id"`
	ServerName    string                    `json:"server_name"`
	ServerIP      string                    `json:"server_ip"`
	Environment   string                    `json:"environment"`
	Role          entities.AccessRole       `json:"role"`
	Status        string                    `json:"status"`
	GrantType     string                    `json:"grant_type"` // direct, group, project
	GrantedBy     string                    `json:"granted_by"`
	GrantedAt     string                    `json:"granted_at"`
	ExpiresAt     *string                   `json:"expires_at,omitempty"`
	LastUsed      *string                   `json:"last_used,omitempty"`
	UsageCount    int                       `json:"usage_count"`
	Conditions    entities.AccessConditions `json:"conditions"`
	IsActive      bool                      `json:"is_active"`
	InheritedFrom string                    `json:"inherited_from,omitempty"`
}

// UserSessionInfo represents active session information
type UserSessionInfo struct {
	SessionID       string `json:"session_id"`
	ServerID        uint   `json:"server_id"`
	ServerName      string `json:"server_name"`
	ServerIP        string `json:"server_ip"`
	IPAddress       string `json:"ip_address"`
	StartedAt       string `json:"started_at"`
	LastActivity    string `json:"last_activity"`
	Duration        int64  `json:"duration"`
	CommandsCount   int    `json:"commands_count"`
	DataTransferred int64  `json:"data_transferred"`
	ConnectionType  string `json:"connection_type"`
	IsActive        bool   `json:"is_active"`
}

// UsersSummary represents summary of users
type UsersSummary struct {
	Total        int64            `json:"total"`
	Active       int64            `json:"active"`
	Inactive     int64            `json:"inactive"`
	Banned       int64            `json:"banned"`
	ByRole       map[string]int64 `json:"by_role"`
	ByDepartment map[string]int64 `json:"by_department"`
	WithSSHKeys  int64            `json:"with_ssh_keys"`
	WithAccess   int64            `json:"with_access"`
	OnlineNow    int64            `json:"online_now"`
}

// CreateSSHKeyRequest represents request to create SSH key
type CreateSSHKeyRequest struct {
	Name      string     `json:"name" validate:"required,min=1,max=100"`
	PublicKey string     `json:"public_key" validate:"required"`
	Comment   string     `json:"comment,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// UpdateSSHKeyRequest represents request to update SSH key
type UpdateSSHKeyRequest struct {
	Name      *string    `json:"name,omitempty" validate:"omitempty,min=1,max=100"`
	Comment   *string    `json:"comment,omitempty"`
	IsActive  *bool      `json:"is_active,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// ChangePasswordRequest represents request to change password
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8"`
	ConfirmPassword string `json:"confirm_password" validate:"required"`
}

// ResetPasswordRequest represents request to reset password
type ResetPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// UpdateProfileRequest represents request to update user profile
type UpdateProfileRequest struct {
	FullName   *string `json:"full_name,omitempty" validate:"omitempty,min=1,max=255"`
	Email      *string `json:"email,omitempty" validate:"omitempty,email"`
	Department *string `json:"department,omitempty" validate:"omitempty,max=100"`
}

// UserProfileResponse represents user profile response
type UserProfileResponse struct {
	User           *entities.User          `json:"user"`
	Stats          *repositories.UserStats `json:"stats"`
	Groups         []UserGroupInfo         `json:"groups"`
	Projects       []UserProjectInfo       `json:"projects"`
	SSHKeys        []entities.SSHKey       `json:"ssh_keys"`
	RecentActivity []repositories.Activity `json:"recent_activity"`
	Permissions    []string                `json:"permissions"`
	Preferences    *UserPreferences        `json:"preferences"`
	SecurityInfo   *UserSecurityInfo       `json:"security_info"`
}

// UserPreferences represents user preferences
type UserPreferences struct {
	Theme              string            `json:"theme"`
	Language           string            `json:"language"`
	Timezone           string            `json:"timezone"`
	EmailNotifications bool              `json:"email_notifications"`
	SlackNotifications bool              `json:"slack_notifications"`
	CustomSettings     map[string]string `json:"custom_settings"`
}

// UserSecurityInfo represents user security information
type UserSecurityInfo struct {
	LastLogin             *string  `json:"last_login,omitempty"`
	LoginCount            int64    `json:"login_count"`
	PasswordLastChanged   *string  `json:"password_last_changed,omitempty"`
	FailedLoginAttempts   int      `json:"failed_login_attempts"`
	AccountLockedUntil    *string  `json:"account_locked_until,omitempty"`
	TwoFactorEnabled      bool     `json:"two_factor_enabled"`
	SecurityQuestions     int      `json:"security_questions"`
	TrustedDevices        int      `json:"trusted_devices"`
	ActiveSessions        int      `json:"active_sessions"`
	SuspiciousActivities  []string `json:"suspicious_activities"`
	PasswordStrengthScore int      `json:"password_strength_score"`
	RequiresPasswordReset bool     `json:"requires_password_reset"`
}

// AddUserToGroupRequest represents request to add user to group
type AddUserToGroupRequest struct {
	GroupIDs []uint `json:"group_ids" validate:"required,min=1,max=50"`
}

// RemoveUserFromGroupRequest represents request to remove user from group
type RemoveUserFromGroupRequest struct {
	GroupIDs []uint `json:"group_ids" validate:"required,min=1,max=50"`
}

// AddUserToProjectRequest represents request to add user to project
type AddUserToProjectRequest struct {
	ProjectIDs []uint `json:"project_ids" validate:"required,min=1,max=50"`
	Role       string `json:"role,omitempty" validate:"omitempty,oneof=owner member viewer"`
}

// RemoveUserFromProjectRequest represents request to remove user from project
type RemoveUserFromProjectRequest struct {
	ProjectIDs []uint `json:"project_ids" validate:"required,min=1,max=50"`
}

// UserSearchFilters represents user search filters
type UserSearchFilters struct {
	Role            string  `json:"role,omitempty"`
	Status          string  `json:"status,omitempty"`
	Department      string  `json:"department,omitempty"`
	HasSSHKeys      *bool   `json:"has_ssh_keys,omitempty"`
	InGroup         *uint   `json:"in_group,omitempty"`
	InProject       *uint   `json:"in_project,omitempty"`
	LastLoginBefore *string `json:"last_login_before,omitempty"`
	LastLoginAfter  *string `json:"last_login_after,omitempty"`
	IsOnline        *bool   `json:"is_online,omitempty"`
	MinAccessCount  *int    `json:"min_access_count,omitempty"`
	MaxAccessCount  *int    `json:"max_access_count,omitempty"`
}

// BulkCreateUsersRequest represents bulk user creation request
type BulkCreateUsersRequest struct {
	Users []CreateUserRequest `json:"users" validate:"required,min=1,max=100"`
}

// BulkUpdateUsersRequest represents bulk user update request
type BulkUpdateUsersRequest struct {
	Updates []UserUpdateItem `json:"updates" validate:"required,min=1,max=100"`
}

// UserUpdateItem represents single user update in bulk operation
type UserUpdateItem struct {
	ID   uint              `json:"id" validate:"required"`
	Data UpdateUserRequest `json:"data"`
}

// UserActivity represents user activity information
type UserActivity struct {
	UserID           uint                         `json:"user_id"`
	Username         string                       `json:"username"`
	TimeRange        repositories.TimeRange       `json:"time_range"`
	TotalActions     int64                        `json:"total_actions"`
	ServerAccess     int64                        `json:"server_access"`
	CommandsExecuted int64                        `json:"commands_executed"`
	DataTransferred  int64                        `json:"data_transferred"`
	FailedAttempts   int64                        `json:"failed_attempts"`
	LoginCount       int64                        `json:"login_count"`
	ActivityByDay    []DailyUserActivity          `json:"activity_by_day"`
	TopServers       []ServerAccessSummary        `json:"top_servers"`
	RecentSessions   []repositories.AccessSession `json:"recent_sessions"`
	RecentActions    []repositories.Activity      `json:"recent_actions"`
	SecurityEvents   []SecurityEvent              `json:"security_events"`
	Stats            *UserActivityStats           `json:"stats"`
}

// DailyUserActivity represents daily user activity
type DailyUserActivity struct {
	Date            string `json:"date"`
	Actions         int64  `json:"actions"`
	ServerAccess    int64  `json:"server_access"`
	Commands        int64  `json:"commands"`
	DataTransferred int64  `json:"data_transferred"`
	FailedAttempts  int64  `json:"failed_attempts"`
	LoginCount      int64  `json:"login_count"`
	OnlineTime      int64  `json:"online_time"`
}

// ServerAccessSummary represents server access summary
type ServerAccessSummary struct {
	ServerID    uint   `json:"server_id"`
	ServerName  string `json:"server_name"`
	ServerIP    string `json:"server_ip"`
	Environment string `json:"environment"`
	AccessCount int64  `json:"access_count"`
	LastAccess  string `json:"last_access"`
	TotalTime   int64  `json:"total_time"`
	Commands    int64  `json:"commands"`
}

// SecurityEvent represents security event
type SecurityEvent struct {
	EventID     string `json:"event_id"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	IPAddress   string `json:"ip_address"`
	UserAgent   string `json:"user_agent"`
	Timestamp   string `json:"timestamp"`
	Status      string `json:"status"`
	Details     string `json:"details,omitempty"`
}

// UserActivityStats represents user activity statistics
type UserActivityStats struct {
	TotalSessions       int64   `json:"total_sessions"`
	ActiveSessions      int64   `json:"active_sessions"`
	AverageSessionTime  float64 `json:"average_session_time"`
	TotalCommands       int64   `json:"total_commands"`
	TotalDataTransfer   int64   `json:"total_data_transfer"`
	ServersAccessed     int64   `json:"servers_accessed"`
	GroupsCount         int64   `json:"groups_count"`
	ProjectsCount       int64   `json:"projects_count"`
	FailedLoginAttempts int64   `json:"failed_login_attempts"`
	SuccessfulLogins    int64   `json:"successful_logins"`
	SecurityIncidents   int64   `json:"security_incidents"`
	LastPasswordChange  *string `json:"last_password_change,omitempty"`
}

// UserAccessHistoryRequest represents request for user access history
type UserAccessHistoryRequest struct {
	ServerID    *uint  `json:"server_id,omitempty"`
	Environment string `json:"environment,omitempty"`
	StartDate   string `json:"start_date,omitempty"`
	EndDate     string `json:"end_date,omitempty"`
	Status      string `json:"status,omitempty"`
	Page        int    `json:"page,omitempty"`
	PageSize    int    `json:"page_size,omitempty"`
	SortBy      string `json:"sort_by,omitempty"`
	SortOrder   string `json:"sort_order,omitempty"`
}

// UserAccessHistoryResponse represents user access history response
type UserAccessHistoryResponse struct {
	History    []UserAccessHistoryItem        `json:"history"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *AccessHistorySummary          `json:"summary"`
}

// UserAccessHistoryItem represents single access history item
type UserAccessHistoryItem struct {
	SessionID         string  `json:"session_id"`
	ServerID          uint    `json:"server_id"`
	ServerName        string  `json:"server_name"`
	ServerIP          string  `json:"server_ip"`
	Environment       string  `json:"environment"`
	AccessTime        string  `json:"access_time"`
	EndTime           *string `json:"end_time,omitempty"`
	Duration          *int64  `json:"duration,omitempty"`
	IPAddress         string  `json:"ip_address"`
	Commands          int     `json:"commands"`
	DataTransferred   int64   `json:"data_transferred"`
	ConnectionType    string  `json:"connection_type"`
	Status            string  `json:"status"`
	ErrorMessage      string  `json:"error_message,omitempty"`
	TerminationReason string  `json:"termination_reason,omitempty"`
}

// AccessHistorySummary represents access history summary
type AccessHistorySummary struct {
	TotalSessions          int64                `json:"total_sessions"`
	SuccessfulSessions     int64                `json:"successful_sessions"`
	FailedSessions         int64                `json:"failed_sessions"`
	TotalDuration          int64                `json:"total_duration"`
	AverageDuration        float64              `json:"average_duration"`
	TotalCommands          int64                `json:"total_commands"`
	TotalDataTransfer      int64                `json:"total_data_transfer"`
	UniqueServers          int64                `json:"unique_servers"`
	MostAccessedServer     *ServerAccessSummary `json:"most_accessed_server"`
	AccessByEnvironment    map[string]int64     `json:"access_by_environment"`
	AccessByConnectionType map[string]int64     `json:"access_by_connection_type"`
}

// ValidateSSHKeyRequest represents request to validate SSH key
type ValidateSSHKeyRequest struct {
	PublicKey string `json:"public_key" validate:"required"`
}

// ValidateSSHKeyResponse represents SSH key validation response
type ValidateSSHKeyResponse struct {
	IsValid     bool     `json:"is_valid"`
	KeyType     string   `json:"key_type"`
	BitLength   int      `json:"bit_length"`
	Fingerprint string   `json:"fingerprint"`
	Comment     string   `json:"comment"`
	IsSecure    bool     `json:"is_secure"`
	Warnings    []string `json:"warnings,omitempty"`
	Errors      []string `json:"errors,omitempty"`
}

// UserDashboardData represents user dashboard data
type UserDashboardData struct {
	User              *entities.User          `json:"user"`
	Summary           *UserDashboardSummary   `json:"summary"`
	RecentActivity    []repositories.Activity `json:"recent_activity"`
	ActiveSessions    []UserSessionInfo       `json:"active_sessions"`
	AccessibleServers []ServerAccessSummary   `json:"accessible_servers"`
	Notifications     []UserNotification      `json:"notifications"`
	SecurityAlerts    []SecurityEvent         `json:"security_alerts"`
	UpdatedAt         string                  `json:"updated_at"`
}

// UserDashboardSummary represents user dashboard summary
type UserDashboardSummary struct {
	AccessibleServers int64 `json:"accessible_servers"`
	ActiveGrants      int64 `json:"active_grants"`
	ActiveSessions    int64 `json:"active_sessions"`
	GroupsCount       int64 `json:"groups_count"`
	ProjectsCount     int64 `json:"projects_count"`
	SSHKeysCount      int64 `json:"ssh_keys_count"`
	RecentLogins      int64 `json:"recent_logins"`
	PendingRequests   int64 `json:"pending_requests"`
	ExpiringAccess    int64 `json:"expiring_access"`
	SecurityScore     int   `json:"security_score"`
}

// UserNotification represents user notification
type UserNotification struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Title      string                 `json:"title"`
	Message    string                 `json:"message"`
	Priority   string                 `json:"priority"`
	CreatedAt  string                 `json:"created_at"`
	IsRead     bool                   `json:"is_read"`
	ActionURL  string                 `json:"action_url,omitempty"`
	ActionText string                 `json:"action_text,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// UserPermissionsResponse represents user permissions response
type UserPermissionsResponse struct {
	UserID               uint                    `json:"user_id"`
	Username             string                  `json:"username"`
	Role                 string                  `json:"role"`
	DirectPermissions    []string                `json:"direct_permissions"`
	GroupPermissions     []GroupPermissionInfo   `json:"group_permissions"`
	ProjectPermissions   []ProjectPermissionInfo `json:"project_permissions"`
	EffectivePermissions []string                `json:"effective_permissions"`
	AccessibleServers    []ServerAccessInfo      `json:"accessible_servers"`
	Restrictions         []string                `json:"restrictions"`
}

// GroupPermissionInfo represents group permission information
type GroupPermissionInfo struct {
	GroupID     uint     `json:"group_id"`
	GroupName   string   `json:"group_name"`
	Permissions []string `json:"permissions"`
}

// ProjectPermissionInfo represents project permission information
type ProjectPermissionInfo struct {
	ProjectID   uint     `json:"project_id"`
	ProjectName string   `json:"project_name"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

// ServerAccessInfo represents server access information
type ServerAccessInfo struct {
	ServerID    uint                      `json:"server_id"`
	ServerName  string                    `json:"server_name"`
	Environment string                    `json:"environment"`
	Role        entities.AccessRole       `json:"role"`
	AccessType  string                    `json:"access_type"` // direct, group, project
	ExpiresAt   *string                   `json:"expires_at,omitempty"`
	Conditions  entities.AccessConditions `json:"conditions"`
}
