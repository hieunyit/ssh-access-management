package services

import (
	"context"
	"ssh-access-management/internal/domain/entities"
	"ssh-access-management/internal/domain/repositories"
	"time"
)

// AccessService defines access service interface
type AccessService interface {
	// Access Grant Management
	CreateGrant(ctx context.Context, req CreateAccessGrantRequest) (*entities.AccessGrant, error)
	GetGrant(ctx context.Context, id uint) (*entities.AccessGrant, error)
	UpdateGrant(ctx context.Context, id uint, req UpdateAccessGrantRequest) (*entities.AccessGrant, error)
	DeleteGrant(ctx context.Context, id uint) error
	ListGrants(ctx context.Context, req ListAccessGrantsRequest) (*ListAccessGrantsResponse, error)

	// Access Request Management
	CreateRequest(ctx context.Context, req CreateAccessRequestRequest) (*entities.AccessRequest, error)
	GetRequest(ctx context.Context, id uint) (*entities.AccessRequest, error)
	UpdateRequest(ctx context.Context, id uint, req UpdateAccessRequestRequest) (*entities.AccessRequest, error)
	DeleteRequest(ctx context.Context, id uint) error
	ListRequests(ctx context.Context, req ListAccessRequestsRequest) (*ListAccessRequestsResponse, error)

	// Grant Operations
	GrantUserAccess(ctx context.Context, req GrantUserAccessRequest) (*entities.AccessGrant, error)
	GrantGroupAccess(ctx context.Context, req GrantGroupAccessRequest) (*entities.AccessGrant, error)
	GrantProjectAccess(ctx context.Context, req GrantProjectAccessRequest) (*entities.AccessGrant, error)
	RevokeAccess(ctx context.Context, grantID uint, reason string, revokedBy uint) error
	RevokeUserAccess(ctx context.Context, userID, serverID uint, revokedBy uint) error
	RevokeGroupAccess(ctx context.Context, groupID, serverID uint, revokedBy uint) error
	RevokeProjectAccess(ctx context.Context, projectID, serverID uint, revokedBy uint) error

	// Request Operations
	ApproveRequest(ctx context.Context, requestID uint, req ApproveAccessRequestRequest) (*entities.AccessGrant, error)
	RejectRequest(ctx context.Context, requestID uint, req RejectAccessRequestRequest) error
	GetPendingRequests(ctx context.Context, approverID uint) ([]entities.AccessRequest, error)
	GetUserRequests(ctx context.Context, userID uint) ([]entities.AccessRequest, error)
	GetServerRequests(ctx context.Context, serverID uint) ([]entities.AccessRequest, error)

	// Access Queries
	GetUserAccess(ctx context.Context, userID uint) ([]entities.AccessGrant, error)
	GetUserServerAccess(ctx context.Context, userID, serverID uint) (*entities.AccessGrant, error)
	GetGroupAccess(ctx context.Context, groupID uint) ([]entities.AccessGrant, error)
	GetProjectAccess(ctx context.Context, projectID uint) ([]entities.AccessGrant, error)
	GetServerAccess(ctx context.Context, serverID uint) ([]entities.AccessGrant, error)
	GetActiveGrants(ctx context.Context, serverID uint) ([]entities.AccessGrant, error)

	// Effective Access (including inheritance)
	GetUserEffectiveAccess(ctx context.Context, userID uint) (*UserEffectiveAccessResponse, error)
	GetUserEffectiveServerAccess(ctx context.Context, userID, serverID uint) (*repositories.EffectiveAccess, error)
	CheckUserServerAccess(ctx context.Context, userID, serverID uint) (bool, error)
	ValidateAccess(ctx context.Context, userID, serverID uint, req AccessValidationRequest) (*AccessValidationResponse, error)

	// Session Management
	CreateSession(ctx context.Context, req CreateSessionRequest) (*repositories.AccessSession, error)
	GetActiveSession(ctx context.Context, userID, serverID uint) (*repositories.AccessSession, error)
	GetUserActiveSessions(ctx context.Context, userID uint) ([]repositories.AccessSession, error)
	GetServerActiveSessions(ctx context.Context, serverID uint) ([]repositories.AccessSession, error)
	UpdateSessionActivity(ctx context.Context, sessionID string) error
	CloseSession(ctx context.Context, sessionID string, reason string) error
	TerminateSession(ctx context.Context, sessionID string, req TerminateSessionRequest) error

	// Usage Tracking
	RecordAccess(ctx context.Context, grantID uint, sessionInfo SessionInfo) error
	IncrementUsage(ctx context.Context, grantID uint) error
	UpdateLastUsed(ctx context.Context, grantID uint) error
	GetAccessUsageStats(ctx context.Context, grantID uint) (*repositories.AccessUsageStats, error)

	// Access Control and Validation
	CanExecuteCommand(ctx context.Context, userID, serverID uint, command string) (bool, error)
	IsIPAllowed(ctx context.Context, userID, serverID uint, ipAddress string) (bool, error)
	IsTimeAllowed(ctx context.Context, userID, serverID uint) (bool, error)
	ValidateSessionLimits(ctx context.Context, userID, serverID uint) (bool, error)
	CheckAccessConditions(ctx context.Context, userID, serverID uint, req AccessConditionsRequest) (*AccessConditionsResponse, error)

	// Statistics and Analytics
	GetAccessStats(ctx context.Context) (*repositories.AccessStats, error)
	GetUserAccessStats(ctx context.Context, userID uint) (*repositories.UserAccessStats, error)
	GetServerAccessStats(ctx context.Context, serverID uint) (*repositories.ServerAccessStats, error)
	GetAccessTrends(ctx context.Context, days int) ([]repositories.AccessTrend, error)
	GetAccessDashboard(ctx context.Context, userID uint) (*AccessDashboardData, error)

	// Bulk Operations
	BulkGrantAccess(ctx context.Context, req BulkGrantAccessRequest) (*BulkOperationResponse, error)
	BulkRevokeAccess(ctx context.Context, req BulkRevokeAccessRequest) (*BulkOperationResponse, error)
	BulkApproveRequests(ctx context.Context, requestIDs []uint, approvedBy uint) (*BulkOperationResponse, error)
	BulkRejectRequests(ctx context.Context, req BulkRejectRequestsRequest) (*BulkOperationResponse, error)

	// Automated Operations
	ProcessExpiredGrants(ctx context.Context) (*CleanupResult, error)
	ProcessExpiredRequests(ctx context.Context) (*CleanupResult, error)
	ProcessInactiveSessions(ctx context.Context, timeout time.Duration) (*CleanupResult, error)
	AutoGrantFromPolicy(ctx context.Context, userID, serverID uint) (*entities.AccessGrant, error)
	SendExpirationNotifications(ctx context.Context, beforeDays int) (*NotificationResult, error)

	// Access Policy Management
	CreateAccessPolicy(ctx context.Context, req CreateAccessPolicyRequest) (*AccessPolicy, error)
	UpdateAccessPolicy(ctx context.Context, policyID uint, req UpdateAccessPolicyRequest) (*AccessPolicy, error)
	DeleteAccessPolicy(ctx context.Context, policyID uint) error
	GetAccessPolicy(ctx context.Context, policyID uint) (*AccessPolicy, error)
	ListAccessPolicies(ctx context.Context) ([]AccessPolicy, error)
	EvaluateAccessPolicy(ctx context.Context, userID, serverID uint) (*PolicyEvaluationResult, error)

	// Approval Workflow Management
	CreateApprovalWorkflow(ctx context.Context, req CreateApprovalWorkflowRequest) (*ApprovalWorkflow, error)
	UpdateApprovalWorkflow(ctx context.Context, workflowID uint, req UpdateApprovalWorkflowRequest) (*ApprovalWorkflow, error)
	GetApprovalWorkflow(ctx context.Context, workflowID uint) (*ApprovalWorkflow, error)
	GetApprovalChain(ctx context.Context, userID, serverID uint) ([]ApprovalStep, error)
	ProcessApprovalStep(ctx context.Context, stepID uint, req ProcessApprovalStepRequest) error

	// Emergency Access
	GrantEmergencyAccess(ctx context.Context, req EmergencyAccessRequest) (*entities.AccessGrant, error)
	RevokeEmergencyAccess(ctx context.Context, grantID uint, reason string) error
	GetEmergencyAccessRequests(ctx context.Context) ([]EmergencyAccessRequest, error)
	LogEmergencyAccess(ctx context.Context, req EmergencyAccessLog) error

	// Compliance and Auditing
	GetComplianceReport(ctx context.Context, req ComplianceReportRequest) (*ComplianceReport, error)
	GetAccessAuditTrail(ctx context.Context, req AuditTrailRequest) (*AuditTrailResponse, error)
	ExportAccessData(ctx context.Context, req ExportAccessDataRequest) ([]byte, error)
	ValidateComplianceRules(ctx context.Context, grantID uint) (*ComplianceValidationResult, error)
}

// Request/Response DTOs

type CreateAccessGrantRequest struct {
	UserID     *uint                     `json:"user_id,omitempty"`
	GroupID    *uint                     `json:"group_id,omitempty"`
	ProjectID  *uint                     `json:"project_id,omitempty"`
	ServerID   uint                      `json:"server_id" validate:"required"`
	Role       entities.AccessRole       `json:"role" validate:"required"`
	Reason     string                    `json:"reason" validate:"required"`
	ExpiresAt  *time.Time                `json:"expires_at,omitempty"`
	Conditions entities.AccessConditions `json:"conditions,omitempty"`
	NotifyUser bool                      `json:"notify_user,omitempty"`
}

type UpdateAccessGrantRequest struct {
	Role       *entities.AccessRole       `json:"role,omitempty"`
	Status     *entities.AccessStatus     `json:"status,omitempty"`
	ExpiresAt  *time.Time                 `json:"expires_at,omitempty"`
	Conditions *entities.AccessConditions `json:"conditions,omitempty"`
}

type CreateAccessRequestRequest struct {
	ServerID              uint                      `json:"server_id" validate:"required"`
	Role                  entities.AccessRole       `json:"role" validate:"required"`
	Reason                string                    `json:"reason" validate:"required"`
	Duration              int                       `json:"duration" validate:"required,min=1,max=8760"` // Hours
	Conditions            entities.AccessConditions `json:"conditions,omitempty"`
	Urgency               string                    `json:"urgency,omitempty" validate:"omitempty,oneof=low medium high critical"`
	BusinessJustification string                    `json:"business_justification,omitempty"`
}

type UpdateAccessRequestRequest struct {
	Reason     *string                    `json:"reason,omitempty"`
	Duration   *int                       `json:"duration,omitempty"`
	Conditions *entities.AccessConditions `json:"conditions,omitempty"`
	Urgency    *string                    `json:"urgency,omitempty"`
}

type ApproveAccessRequestRequest struct {
	Reason     string                     `json:"reason,omitempty"`
	ExpiresAt  *time.Time                 `json:"expires_at,omitempty"`
	Conditions *entities.AccessConditions `json:"conditions,omitempty"`
	Comments   string                     `json:"comments,omitempty"`
}

type RejectAccessRequestRequest struct {
	Reason   string `json:"reason" validate:"required"`
	Comments string `json:"comments,omitempty"`
}

type ListAccessGrantsRequest struct {
	UserID        *uint      `json:"user_id,omitempty"`
	GroupID       *uint      `json:"group_id,omitempty"`
	ProjectID     *uint      `json:"project_id,omitempty"`
	ServerID      *uint      `json:"server_id,omitempty"`
	Role          string     `json:"role,omitempty"`
	Status        string     `json:"status,omitempty"`
	GrantedBy     *uint      `json:"granted_by,omitempty"`
	IsExpired     *bool      `json:"is_expired,omitempty"`
	IsActive      *bool      `json:"is_active,omitempty"`
	ExpiresAfter  *time.Time `json:"expires_after,omitempty"`
	ExpiresBefore *time.Time `json:"expires_before,omitempty"`
	GrantedAfter  *time.Time `json:"granted_after,omitempty"`
	GrantedBefore *time.Time `json:"granted_before,omitempty"`
	Page          int        `json:"page,omitempty"`
	PageSize      int        `json:"page_size,omitempty"`
	SortBy        string     `json:"sort_by,omitempty"`
	SortOrder     string     `json:"sort_order,omitempty"`
}

type ListAccessGrantsResponse struct {
	Grants     []entities.AccessGrant         `json:"grants"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *AccessGrantsSummary           `json:"summary"`
}

type AccessGrantsSummary struct {
	Total    int64            `json:"total"`
	Active   int64            `json:"active"`
	Expired  int64            `json:"expired"`
	Revoked  int64            `json:"revoked"`
	ByRole   map[string]int64 `json:"by_role"`
	ByStatus map[string]int64 `json:"by_status"`
}

type ListAccessRequestsRequest struct {
	RequesterID   *uint      `json:"requester_id,omitempty"`
	ServerID      *uint      `json:"server_id,omitempty"`
	Role          string     `json:"role,omitempty"`
	Status        string     `json:"status,omitempty"`
	Urgency       string     `json:"urgency,omitempty"`
	ApprovedBy    *uint      `json:"approved_by,omitempty"`
	RejectedBy    *uint      `json:"rejected_by,omitempty"`
	CreatedAfter  *time.Time `json:"created_after,omitempty"`
	CreatedBefore *time.Time `json:"created_before,omitempty"`
	Page          int        `json:"page,omitempty"`
	PageSize      int        `json:"page_size,omitempty"`
	SortBy        string     `json:"sort_by,omitempty"`
	SortOrder     string     `json:"sort_order,omitempty"`
}

type ListAccessRequestsResponse struct {
	Requests   []entities.AccessRequest       `json:"requests"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *AccessRequestsSummary         `json:"summary"`
}

type AccessRequestsSummary struct {
	Total     int64            `json:"total"`
	Pending   int64            `json:"pending"`
	Approved  int64            `json:"approved"`
	Rejected  int64            `json:"rejected"`
	Expired   int64            `json:"expired"`
	ByRole    map[string]int64 `json:"by_role"`
	ByStatus  map[string]int64 `json:"by_status"`
	ByUrgency map[string]int64 `json:"by_urgency"`
}

type GrantUserAccessRequest struct {
	UserID     uint                      `json:"user_id" validate:"required"`
	ServerID   uint                      `json:"server_id" validate:"required"`
	Role       entities.AccessRole       `json:"role" validate:"required"`
	Reason     string                    `json:"reason" validate:"required"`
	ExpiresAt  *time.Time                `json:"expires_at,omitempty"`
	Conditions entities.AccessConditions `json:"conditions,omitempty"`
	GrantedBy  uint                      `json:"granted_by" validate:"required"`
}

type GrantGroupAccessRequest struct {
	GroupID    uint                      `json:"group_id" validate:"required"`
	ServerID   uint                      `json:"server_id" validate:"required"`
	Role       entities.AccessRole       `json:"role" validate:"required"`
	Reason     string                    `json:"reason" validate:"required"`
	ExpiresAt  *time.Time                `json:"expires_at,omitempty"`
	Conditions entities.AccessConditions `json:"conditions,omitempty"`
	GrantedBy  uint                      `json:"granted_by" validate:"required"`
}

type GrantProjectAccessRequest struct {
	ProjectID  uint                      `json:"project_id" validate:"required"`
	ServerID   uint                      `json:"server_id" validate:"required"`
	Role       entities.AccessRole       `json:"role" validate:"required"`
	Reason     string                    `json:"reason" validate:"required"`
	ExpiresAt  *time.Time                `json:"expires_at,omitempty"`
	Conditions entities.AccessConditions `json:"conditions,omitempty"`
	GrantedBy  uint                      `json:"granted_by" validate:"required"`
}

type CreateSessionRequest struct {
	UserID         uint   `json:"user_id" validate:"required"`
	ServerID       uint   `json:"server_id" validate:"required"`
	IPAddress      string `json:"ip_address" validate:"required"`
	UserAgent      string `json:"user_agent,omitempty"`
	ConnectionType string `json:"connection_type" validate:"required,oneof=ssh scp sftp"`
}

type SessionInfo struct {
	SessionID    string `json:"session_id"`
	Command      string `json:"command,omitempty"`
	ExitCode     *int   `json:"exit_code,omitempty"`
	DataTransfer int64  `json:"data_transfer,omitempty"`
}

type AccessValidationRequest struct {
	IPAddress      string `json:"ip_address"`
	Command        string `json:"command,omitempty"`
	ConnectionType string `json:"connection_type"`
	UserAgent      string `json:"user_agent,omitempty"`
}

type AccessValidationResponse struct {
	IsAllowed     bool                      `json:"is_allowed"`
	Grant         *entities.AccessGrant     `json:"grant,omitempty"`
	Reason        string                    `json:"reason,omitempty"`
	Conditions    entities.AccessConditions `json:"conditions"`
	SessionLimits *SessionLimits            `json:"session_limits,omitempty"`
	Warnings      []string                  `json:"warnings,omitempty"`
}

type SessionLimits struct {
	MaxSessions      int   `json:"max_sessions"`
	CurrentSessions  int   `json:"current_sessions"`
	SessionTimeout   int   `json:"session_timeout"`
	RemainingTime    int64 `json:"remaining_time"`
	CanCreateSession bool  `json:"can_create_session"`
}

type AccessConditionsRequest struct {
	IPAddress      string    `json:"ip_address"`
	CurrentTime    time.Time `json:"current_time"`
	SessionCount   int       `json:"session_count"`
	Command        string    `json:"command,omitempty"`
	ConnectionType string    `json:"connection_type"`
}

type AccessConditionsResponse struct {
	IPAllowed       bool     `json:"ip_allowed"`
	TimeAllowed     bool     `json:"time_allowed"`
	SessionAllowed  bool     `json:"session_allowed"`
	CommandAllowed  bool     `json:"command_allowed"`
	AllowedCommands []string `json:"allowed_commands,omitempty"`
	DeniedCommands  []string `json:"denied_commands,omitempty"`
	Restrictions    []string `json:"restrictions,omitempty"`
}

type UserEffectiveAccessResponse struct {
	UserID        uint                           `json:"user_id"`
	Username      string                         `json:"username"`
	TotalServers  int                            `json:"total_servers"`
	DirectAccess  []repositories.EffectiveAccess `json:"direct_access"`
	GroupAccess   []repositories.EffectiveAccess `json:"group_access"`
	ProjectAccess []repositories.EffectiveAccess `json:"project_access"`
	AllAccess     []repositories.EffectiveAccess `json:"all_access"`
	Summary       *EffectiveAccessSummary        `json:"summary"`
}

type EffectiveAccessSummary struct {
	TotalGrants       int64            `json:"total_grants"`
	ActiveGrants      int64            `json:"active_grants"`
	ExpiredGrants     int64            `json:"expired_grants"`
	ExpiringGrants    int64            `json:"expiring_grants"`
	ByRole            map[string]int64 `json:"by_role"`
	ByEnvironment     map[string]int64 `json:"by_environment"`
	ByInheritanceType map[string]int64 `json:"by_inheritance_type"`
}

type BulkGrantAccessRequest struct {
	Grants    []CreateAccessGrantRequest `json:"grants" validate:"required,min=1,max=100"`
	GrantedBy uint                       `json:"granted_by" validate:"required"`
}

type BulkRevokeAccessRequest struct {
	GrantIDs  []uint `json:"grant_ids" validate:"required,min=1,max=100"`
	Reason    string `json:"reason,omitempty"`
	RevokedBy uint   `json:"revoked_by" validate:"required"`
}

type BulkRejectRequestsRequest struct {
	RequestIDs []uint `json:"request_ids" validate:"required,min=1,max=100"`
	Reason     string `json:"reason" validate:"required"`
	RejectedBy uint   `json:"rejected_by" validate:"required"`
}

type BulkOperationResponse struct {
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
	Code    string `json:"code,omitempty"`
}

type CleanupResult struct {
	ProcessedCount int64    `json:"processed_count"`
	CleanedCount   int64    `json:"cleaned_count"`
	ErrorCount     int64    `json:"error_count"`
	Errors         []string `json:"errors,omitempty"`
	Duration       int64    `json:"duration_ms"`
}

type NotificationResult struct {
	SentCount        int64    `json:"sent_count"`
	FailedCount      int64    `json:"failed_count"`
	Recipients       []string `json:"recipients"`
	Errors           []string `json:"errors,omitempty"`
	NotificationType string   `json:"notification_type"`
}

type AccessDashboardData struct {
	User            *entities.User               `json:"user"`
	Summary         *AccessDashboardSummary      `json:"summary"`
	RecentGrants    []entities.AccessGrant       `json:"recent_grants"`
	ActiveSessions  []repositories.AccessSession `json:"active_sessions"`
	PendingRequests []entities.AccessRequest     `json:"pending_requests"`
	ExpiringAccess  []entities.AccessGrant       `json:"expiring_access"`
	Notifications   []AccessNotification         `json:"notifications"`
	QuickActions    []QuickAction                `json:"quick_actions"`
	UpdatedAt       string                       `json:"updated_at"`
}

type AccessDashboardSummary struct {
	TotalGrants       int64 `json:"total_grants"`
	ActiveGrants      int64 `json:"active_grants"`
	ExpiringGrants    int64 `json:"expiring_grants"`
	PendingRequests   int64 `json:"pending_requests"`
	ActiveSessions    int64 `json:"active_sessions"`
	AccessibleServers int64 `json:"accessible_servers"`
	RecentActions     int64 `json:"recent_actions"`
}

type AccessNotification struct {
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

type QuickAction struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
	URL         string `json:"url"`
	Badge       string `json:"badge,omitempty"`
	IsEnabled   bool   `json:"is_enabled"`
}

type AccessPolicy struct {
	ID          uint             `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Type        string           `json:"type"` // auto_grant, auto_deny, approval_required
	Conditions  PolicyConditions `json:"conditions"`
	Actions     PolicyActions    `json:"actions"`
	IsActive    bool             `json:"is_active"`
	Priority    int              `json:"priority"`
	CreatedBy   uint             `json:"created_by"`
	CreatedAt   string           `json:"created_at"`
	UpdatedAt   string           `json:"updated_at"`
}

type PolicyConditions struct {
	UserGroups         []uint                     `json:"user_groups,omitempty"`
	UserRoles          []string                   `json:"user_roles,omitempty"`
	ServerEnvironments []string                   `json:"server_environments,omitempty"`
	ServerPlatforms    []string                   `json:"server_platforms,omitempty"`
	ServerTags         []string                   `json:"server_tags,omitempty"`
	TimeRestrictions   *entities.TimeRestrictions `json:"time_restrictions,omitempty"`
	IPRestrictions     []string                   `json:"ip_restrictions,omitempty"`
	BusinessHours      bool                       `json:"business_hours,omitempty"`
}

type PolicyActions struct {
	GrantRole        entities.AccessRole       `json:"grant_role,omitempty"`
	Duration         int                       `json:"duration,omitempty"` // Hours
	RequireApproval  bool                      `json:"require_approval,omitempty"`
	ApprovalWorkflow uint                      `json:"approval_workflow,omitempty"`
	Conditions       entities.AccessConditions `json:"conditions,omitempty"`
	Notifications    []NotificationAction      `json:"notifications,omitempty"`
}

type NotificationAction struct {
	Type       string   `json:"type"` // email, slack, teams
	Recipients []string `json:"recipients"`
	Template   string   `json:"template"`
}

type CreateAccessPolicyRequest struct {
	Name        string           `json:"name" validate:"required"`
	Description string           `json:"description,omitempty"`
	Type        string           `json:"type" validate:"required,oneof=auto_grant auto_deny approval_required"`
	Conditions  PolicyConditions `json:"conditions"`
	Actions     PolicyActions    `json:"actions"`
	IsActive    bool             `json:"is_active"`
	Priority    int              `json:"priority"`
}

type UpdateAccessPolicyRequest struct {
	Name        *string           `json:"name,omitempty"`
	Description *string           `json:"description,omitempty"`
	Type        *string           `json:"type,omitempty"`
	Conditions  *PolicyConditions `json:"conditions,omitempty"`
	Actions     *PolicyActions    `json:"actions,omitempty"`
	IsActive    *bool             `json:"is_active,omitempty"`
	Priority    *int              `json:"priority,omitempty"`
}

type PolicyEvaluationResult struct {
	MatchedPolicies  []AccessPolicy            `json:"matched_policies"`
	FinalDecision    string                    `json:"final_decision"` // grant, deny, approval_required
	GrantedRole      entities.AccessRole       `json:"granted_role,omitempty"`
	Duration         int                       `json:"duration,omitempty"`
	Conditions       entities.AccessConditions `json:"conditions,omitempty"`
	RequiresApproval bool                      `json:"requires_approval"`
	ApprovalWorkflow uint                      `json:"approval_workflow,omitempty"`
	Explanation      string                    `json:"explanation"`
}

type ApprovalWorkflow struct {
	ID          uint           `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Steps       []ApprovalStep `json:"steps"`
	IsActive    bool           `json:"is_active"`
	CreatedBy   uint           `json:"created_by"`
	CreatedAt   string         `json:"created_at"`
	UpdatedAt   string         `json:"updated_at"`
}

type ApprovalStep struct {
	ID            uint   `json:"id"`
	WorkflowID    uint   `json:"workflow_id"`
	StepNumber    int    `json:"step_number"`
	Name          string `json:"name"`
	ApproverType  string `json:"approver_type"` // user, group, role, manager
	ApproverIDs   []uint `json:"approver_ids"`
	RequiredCount int    `json:"required_count"` // Number of approvals needed
	IsParallel    bool   `json:"is_parallel"`    // All approvers or just required count
	TimeoutHours  int    `json:"timeout_hours"`
	IsOptional    bool   `json:"is_optional"`
}

type CreateApprovalWorkflowRequest struct {
	Name        string         `json:"name" validate:"required"`
	Description string         `json:"description,omitempty"`
	Steps       []ApprovalStep `json:"steps" validate:"required,min=1"`
	IsActive    bool           `json:"is_active"`
}

type UpdateApprovalWorkflowRequest struct {
	Name        *string        `json:"name,omitempty"`
	Description *string        `json:"description,omitempty"`
	Steps       []ApprovalStep `json:"steps,omitempty"`
	IsActive    *bool          `json:"is_active,omitempty"`
}

type ProcessApprovalStepRequest struct {
	Action   string `json:"action" validate:"required,oneof=approve reject"`
	Comments string `json:"comments,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type EmergencyAccessRequest struct {
	UserID        uint   `json:"user_id" validate:"required"`
	ServerID      uint   `json:"server_id" validate:"required"`
	Reason        string `json:"reason" validate:"required"`
	Justification string `json:"justification" validate:"required"`
	Duration      int    `json:"duration" validate:"required,min=1,max=24"` // Max 24 hours
	ApprovedBy    *uint  `json:"approved_by,omitempty"`
	CreatedAt     string `json:"created_at"`
	Status        string `json:"status"`
}

type EmergencyAccessLog struct {
	GrantID   uint   `json:"grant_id"`
	UserID    uint   `json:"user_id"`
	ServerID  uint   `json:"server_id"`
	Action    string `json:"action"`
	Reason    string `json:"reason"`
	IPAddress string `json:"ip_address"`
	UserAgent string `json:"user_agent"`
	SessionID string `json:"session_id,omitempty"`
}

type ComplianceReportRequest struct {
	StartDate      string `json:"start_date" validate:"required"`
	EndDate        string `json:"end_date" validate:"required"`
	UserIDs        []uint `json:"user_ids,omitempty"`
	ServerIDs      []uint `json:"server_ids,omitempty"`
	Environment    string `json:"environment,omitempty"`
	ReportType     string `json:"report_type" validate:"required,oneof=access_review privileged_access emergency_access"`
	Format         string `json:"format" validate:"required,oneof=json csv xlsx pdf"`
	IncludeDetails bool   `json:"include_details"`
}

type ComplianceReport struct {
	ReportType      string                   `json:"report_type"`
	TimeRange       repositories.TimeRange   `json:"time_range"`
	Summary         *ComplianceReportSummary `json:"summary"`
	Violations      []ComplianceViolation    `json:"violations"`
	Recommendations []string                 `json:"recommendations"`
	Details         []ComplianceDetail       `json:"details"`
	GeneratedAt     string                   `json:"generated_at"`
	GeneratedBy     string                   `json:"generated_by"`
}

type ComplianceReportSummary struct {
	TotalAccess     int64   `json:"total_access"`
	CompliantAccess int64   `json:"compliant_access"`
	ViolationsCount int64   `json:"violations_count"`
	ComplianceScore float64 `json:"compliance_score"`
	RiskLevel       string  `json:"risk_level"`
}

type ComplianceViolation struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Count       int64  `json:"count"`
	UserID      *uint  `json:"user_id,omitempty"`
	ServerID    *uint  `json:"server_id,omitempty"`
	GrantID     *uint  `json:"grant_id,omitempty"`
	Details     string `json:"details"`
}

type ComplianceDetail struct {
	AccessID   uint     `json:"access_id"`
	UserID     uint     `json:"user_id"`
	Username   string   `json:"username"`
	ServerID   uint     `json:"server_id"`
	ServerName string   `json:"server_name"`
	AccessType string   `json:"access_type"`
	GrantedAt  string   `json:"granted_at"`
	ExpiresAt  *string  `json:"expires_at,omitempty"`
	LastUsed   *string  `json:"last_used,omitempty"`
	Status     string   `json:"status"`
	Compliant  bool     `json:"compliant"`
	Issues     []string `json:"issues"`
}

type AuditTrailRequest struct {
	UserID    *uint  `json:"user_id,omitempty"`
	ServerID  *uint  `json:"server_id,omitempty"`
	GrantID   *uint  `json:"grant_id,omitempty"`
	Action    string `json:"action,omitempty"`
	StartDate string `json:"start_date,omitempty"`
	EndDate   string `json:"end_date,omitempty"`
	Page      int    `json:"page,omitempty"`
	PageSize  int    `json:"page_size,omitempty"`
}

type AuditTrailResponse struct {
	Entries    []AuditTrailEntry              `json:"entries"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *AuditTrailSummary             `json:"summary"`
}

type AuditTrailEntry struct {
	ID         uint                   `json:"id"`
	Action     string                 `json:"action"`
	UserID     *uint                  `json:"user_id,omitempty"`
	Username   string                 `json:"username,omitempty"`
	TargetType string                 `json:"target_type"`
	TargetID   uint                   `json:"target_id"`
	TargetName string                 `json:"target_name"`
	Details    map[string]interface{} `json:"details"`
	IPAddress  string                 `json:"ip_address"`
	UserAgent  string                 `json:"user_agent"`
	Status     string                 `json:"status"`
	Timestamp  string                 `json:"timestamp"`
}

type AuditTrailSummary struct {
	TotalEntries int64                  `json:"total_entries"`
	ByAction     map[string]int64       `json:"by_action"`
	ByUser       map[string]int64       `json:"by_user"`
	ByStatus     map[string]int64       `json:"by_status"`
	DateRange    repositories.TimeRange `json:"date_range"`
}

type ExportAccessDataRequest struct {
	Format         string `json:"format" validate:"required,oneof=json csv xlsx"`
	UserIDs        []uint `json:"user_ids,omitempty"`
	ServerIDs      []uint `json:"server_ids,omitempty"`
	StartDate      string `json:"start_date,omitempty"`
	EndDate        string `json:"end_date,omitempty"`
	IncludeExpired bool   `json:"include_expired"`
	IncludeRevoked bool   `json:"include_revoked"`
}

type ComplianceValidationResult struct {
	IsCompliant     bool                  `json:"is_compliant"`
	Score           float64               `json:"score"`
	Violations      []ComplianceViolation `json:"violations"`
	Recommendations []string              `json:"recommendations"`
	CheckedRules    []ComplianceRule      `json:"checked_rules"`
	ValidatedAt     string                `json:"validated_at"`
}

type ComplianceRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Passed      bool   `json:"passed"`
	Message     string `json:"message,omitempty"`
}

type TerminateSessionRequest struct {
	Reason string `json:"reason,omitempty"`
	Force  bool   `json:"force,omitempty"`
}
