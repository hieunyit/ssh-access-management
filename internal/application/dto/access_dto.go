package dto

import (
	"ssh-access-management/internal/domain/entities"
	"ssh-access-management/internal/domain/repositories"
	"time"
)

// CreateAccessGrantRequest represents request to create access grant
type CreateAccessGrantRequest struct {
	UserID     *uint                     `json:"user_id,omitempty"`
	GroupID    *uint                     `json:"group_id,omitempty"`
	ProjectID  *uint                     `json:"project_id,omitempty"`
	ServerID   uint                      `json:"server_id" validate:"required"`
	Role       entities.AccessRole       `json:"role" validate:"required,access_role"`
	Reason     string                    `json:"reason" validate:"required"`
	ExpiresAt  *time.Time                `json:"expires_at,omitempty"`
	Conditions entities.AccessConditions `json:"conditions,omitempty"`
}

// UpdateAccessGrantRequest represents request to update access grant
type UpdateAccessGrantRequest struct {
	Role       *entities.AccessRole       `json:"role,omitempty" validate:"omitempty,access_role"`
	Status     *entities.AccessStatus     `json:"status,omitempty"`
	ExpiresAt  *time.Time                 `json:"expires_at,omitempty"`
	Conditions *entities.AccessConditions `json:"conditions,omitempty"`
}

// CreateAccessRequestRequest represents request to create access request
type CreateAccessRequestRequest struct {
	ServerID   uint                      `json:"server_id" validate:"required"`
	Role       entities.AccessRole       `json:"role" validate:"required,access_role"`
	Reason     string                    `json:"reason" validate:"required"`
	Duration   int                       `json:"duration" validate:"required,min=1,max=8760"` // Max 1 year in hours
	Conditions entities.AccessConditions `json:"conditions,omitempty"`
}

// ApproveAccessRequestRequest represents request to approve access request
type ApproveAccessRequestRequest struct {
	Reason     string                     `json:"reason,omitempty"`
	ExpiresAt  *time.Time                 `json:"expires_at,omitempty"`
	Conditions *entities.AccessConditions `json:"conditions,omitempty"`
}

// RejectAccessRequestRequest represents request to reject access request
type RejectAccessRequestRequest struct {
	Reason string `json:"reason" validate:"required"`
}

// ListAccessGrantsRequest represents request to list access grants
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

// ListAccessGrantsResponse represents response for listing access grants
type ListAccessGrantsResponse struct {
	Grants     []entities.AccessGrant         `json:"grants"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *AccessGrantsSummary           `json:"summary"`
}

// ListAccessRequestsRequest represents request to list access requests
type ListAccessRequestsRequest struct {
	RequesterID   *uint      `json:"requester_id,omitempty"`
	ServerID      *uint      `json:"server_id,omitempty"`
	Role          string     `json:"role,omitempty"`
	Status        string     `json:"status,omitempty"`
	ApprovedBy    *uint      `json:"approved_by,omitempty"`
	RejectedBy    *uint      `json:"rejected_by,omitempty"`
	CreatedAfter  *time.Time `json:"created_after,omitempty"`
	CreatedBefore *time.Time `json:"created_before,omitempty"`
	Page          int        `json:"page,omitempty"`
	PageSize      int        `json:"page_size,omitempty"`
	SortBy        string     `json:"sort_by,omitempty"`
	SortOrder     string     `json:"sort_order,omitempty"`
}

// ListAccessRequestsResponse represents response for listing access requests
type ListAccessRequestsResponse struct {
	Requests   []entities.AccessRequest       `json:"requests"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *AccessRequestsSummary         `json:"summary"`
}

// AccessGrantsSummary represents summary of access grants
type AccessGrantsSummary struct {
	Total    int64            `json:"total"`
	Active   int64            `json:"active"`
	Expired  int64            `json:"expired"`
	Revoked  int64            `json:"revoked"`
	ByRole   map[string]int64 `json:"by_role"`
	ByStatus map[string]int64 `json:"by_status"`
}

// AccessRequestsSummary represents summary of access requests
type AccessRequestsSummary struct {
	Total    int64            `json:"total"`
	Pending  int64            `json:"pending"`
	Approved int64            `json:"approved"`
	Rejected int64            `json:"rejected"`
	Expired  int64            `json:"expired"`
	ByRole   map[string]int64 `json:"by_role"`
	ByStatus map[string]int64 `json:"by_status"`
	ByServer map[string]int64 `json:"by_server"`
}

// GrantAccessBatchRequest represents batch access grant request
type GrantAccessBatchRequest struct {
	Grants []CreateAccessGrantRequest `json:"grants" validate:"required,min=1,max=100"`
}

// RevokeAccessBatchRequest represents batch access revoke request
type RevokeAccessBatchRequest struct {
	GrantIDs []uint `json:"grant_ids" validate:"required,min=1,max=100"`
	Reason   string `json:"reason,omitempty"`
}

// AccessSessionResponse represents access session response
type AccessSessionResponse struct {
	Sessions   []repositories.AccessSession   `json:"sessions"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *SessionsSummary               `json:"summary"`
}

// SessionsSummary represents summary of sessions
type SessionsSummary struct {
	Total             int64   `json:"total"`
	Active            int64   `json:"active"`
	Ended             int64   `json:"ended"`
	AverageDuration   float64 `json:"average_duration"`
	TotalDataTransfer int64   `json:"total_data_transfer"`
}

// UserEffectiveAccessResponse represents user's effective access
type UserEffectiveAccessResponse struct {
	UserID        uint                           `json:"user_id"`
	Username      string                         `json:"username"`
	TotalServers  int                            `json:"total_servers"`
	DirectAccess  []repositories.EffectiveAccess `json:"direct_access"`
	GroupAccess   []repositories.EffectiveAccess `json:"group_access"`
	ProjectAccess []repositories.EffectiveAccess `json:"project_access"`
	AllAccess     []repositories.EffectiveAccess `json:"all_access"`
}

// AccessStatsResponse represents access statistics
type AccessStatsResponse struct {
	Stats  *repositories.AccessStats  `json:"stats"`
	Trends []repositories.AccessTrend `json:"trends"`
}

// TerminateSessionRequest represents request to terminate session
type TerminateSessionRequest struct {
	Reason string `json:"reason,omitempty"`
}

// AccessControlRequest represents access control request
type AccessControlRequest struct {
	UserID   uint   `json:"user_id" validate:"required"`
	ServerID uint   `json:"server_id" validate:"required"`
	Action   string `json:"action" validate:"required,oneof=allow deny"`
	Reason   string `json:"reason,omitempty"`
}
