package repositories

import (
	"context"
	"fmt"
	"strings"
	"time"

	"ssh-access-management/internal/domain/entities"
	"ssh-access-management/internal/domain/repositories"

	"gorm.io/gorm"
)

type accessRepository struct {
	db *gorm.DB
}

// NewAccessRepository creates a new access repository
func NewAccessRepository(db *gorm.DB) repositories.AccessRepository {
	return &accessRepository{db: db}
}

// CreateGrant creates a new access grant
func (r *accessRepository) CreateGrant(ctx context.Context, grant *entities.AccessGrant) error {
	if err := r.db.WithContext(ctx).Create(grant).Error; err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return entities.ErrAccessAlreadyExists
		}
		return fmt.Errorf("failed to create access grant: %w", err)
	}
	return nil
}

// GetGrantByID retrieves an access grant by ID
func (r *accessRepository) GetGrantByID(ctx context.Context, id uint) (*entities.AccessGrant, error) {
	var grant entities.AccessGrant
	if err := r.db.WithContext(ctx).
		Preload("User").
		Preload("Group").
		Preload("Project").
		Preload("Server").
		Preload("GrantedByUser").
		Preload("RevokedByUser").
		First(&grant, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, entities.ErrAccessNotFound
		}
		return nil, fmt.Errorf("failed to get access grant: %w", err)
	}
	return &grant, nil
}

// UpdateGrant updates an access grant
func (r *accessRepository) UpdateGrant(ctx context.Context, grant *entities.AccessGrant) error {
	if err := r.db.WithContext(ctx).Save(grant).Error; err != nil {
		return fmt.Errorf("failed to update access grant: %w", err)
	}
	return nil
}

// DeleteGrant deletes an access grant
func (r *accessRepository) DeleteGrant(ctx context.Context, id uint) error {
	if err := r.db.WithContext(ctx).Delete(&entities.AccessGrant{}, id).Error; err != nil {
		return fmt.Errorf("failed to delete access grant: %w", err)
	}
	return nil
}

// ListGrants retrieves access grants with filtering and pagination
func (r *accessRepository) ListGrants(ctx context.Context, filter repositories.AccessGrantFilter) ([]entities.AccessGrant, *repositories.PaginationResult, error) {
	var grants []entities.AccessGrant
	var total int64

	query := r.db.WithContext(ctx).Model(&entities.AccessGrant{})

	// Apply filters
	query = r.applyAccessGrantFilters(query, filter)

	// Count total records
	if err := query.Count(&total).Error; err != nil {
		return nil, nil, fmt.Errorf("failed to count access grants: %w", err)
	}

	// Apply pagination and sorting
	query = r.applyPaginationAndSorting(query, filter.Pagination, filter.SortBy, filter.SortOrder)

	// Preload associations
	query = query.Preload("User").Preload("Group").Preload("Project").
		Preload("Server").Preload("GrantedByUser").Preload("RevokedByUser")

	if err := query.Find(&grants).Error; err != nil {
		return nil, nil, fmt.Errorf("failed to list access grants: %w", err)
	}

	pagination := repositories.NewPaginationResult(filter.Pagination.Page, filter.Pagination.PageSize, total)
	return grants, pagination, nil
}

// CreateRequest creates a new access request
func (r *accessRepository) CreateRequest(ctx context.Context, request *entities.AccessRequest) error {
	if err := r.db.WithContext(ctx).Create(request).Error; err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return entities.ErrRequestAlreadyExists
		}
		return fmt.Errorf("failed to create access request: %w", err)
	}
	return nil
}

// GetRequestByID retrieves an access request by ID
func (r *accessRepository) GetRequestByID(ctx context.Context, id uint) (*entities.AccessRequest, error) {
	var request entities.AccessRequest
	if err := r.db.WithContext(ctx).
		Preload("Requester").
		Preload("Server").
		Preload("ApprovedByUser").
		Preload("RejectedByUser").
		First(&request, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, entities.ErrAccessRequestNotFound
		}
		return nil, fmt.Errorf("failed to get access request: %w", err)
	}
	return &request, nil
}

// UpdateRequest updates an access request
func (r *accessRepository) UpdateRequest(ctx context.Context, request *entities.AccessRequest) error {
	if err := r.db.WithContext(ctx).Save(request).Error; err != nil {
		return fmt.Errorf("failed to update access request: %w", err)
	}
	return nil
}

// DeleteRequest deletes an access request
func (r *accessRepository) DeleteRequest(ctx context.Context, id uint) error {
	if err := r.db.WithContext(ctx).Delete(&entities.AccessRequest{}, id).Error; err != nil {
		return fmt.Errorf("failed to delete access request: %w", err)
	}
	return nil
}

// ListRequests retrieves access requests with filtering and pagination
func (r *accessRepository) ListRequests(ctx context.Context, filter repositories.AccessRequestFilter) ([]entities.AccessRequest, *repositories.PaginationResult, error) {
	var requests []entities.AccessRequest
	var total int64

	query := r.db.WithContext(ctx).Model(&entities.AccessRequest{})

	// Apply filters
	query = r.applyAccessRequestFilters(query, filter)

	// Count total records
	if err := query.Count(&total).Error; err != nil {
		return nil, nil, fmt.Errorf("failed to count access requests: %w", err)
	}

	// Apply pagination and sorting
	query = r.applyPaginationAndSorting(query, filter.Pagination, filter.SortBy, filter.SortOrder)

	// Preload associations
	query = query.Preload("Requester").Preload("Server").
		Preload("ApprovedByUser").Preload("RejectedByUser")

	if err := query.Find(&requests).Error; err != nil {
		return nil, nil, fmt.Errorf("failed to list access requests: %w", err)
	}

	pagination := repositories.NewPaginationResult(filter.Pagination.Page, filter.Pagination.PageSize, total)
	return requests, pagination, nil
}

// GrantUserAccess grants access to a user
func (r *accessRepository) GrantUserAccess(ctx context.Context, userID, serverID, grantedBy uint, role entities.AccessRole, expiresAt *time.Time, conditions entities.AccessConditions) (*entities.AccessGrant, error) {
	grant := &entities.AccessGrant{
		UserID:     &userID,
		ServerID:   serverID,
		Role:       role,
		Status:     entities.AccessStatusActive,
		GrantedBy:  grantedBy,
		GrantedAt:  time.Now(),
		ExpiresAt:  expiresAt,
		Conditions: conditions,
	}

	if err := r.CreateGrant(ctx, grant); err != nil {
		return nil, err
	}

	return r.GetGrantByID(ctx, grant.ID)
}

// GrantGroupAccess grants access to a group
func (r *accessRepository) GrantGroupAccess(ctx context.Context, groupID, serverID, grantedBy uint, role entities.AccessRole, expiresAt *time.Time, conditions entities.AccessConditions) (*entities.AccessGrant, error) {
	grant := &entities.AccessGrant{
		GroupID:    &groupID,
		ServerID:   serverID,
		Role:       role,
		Status:     entities.AccessStatusActive,
		GrantedBy:  grantedBy,
		GrantedAt:  time.Now(),
		ExpiresAt:  expiresAt,
		Conditions: conditions,
	}

	if err := r.CreateGrant(ctx, grant); err != nil {
		return nil, err
	}

	return r.GetGrantByID(ctx, grant.ID)
}

// GrantProjectAccess grants access to a project
func (r *accessRepository) GrantProjectAccess(ctx context.Context, projectID, serverID, grantedBy uint, role entities.AccessRole, expiresAt *time.Time, conditions entities.AccessConditions) (*entities.AccessGrant, error) {
	grant := &entities.AccessGrant{
		ProjectID:  &projectID,
		ServerID:   serverID,
		Role:       role,
		Status:     entities.AccessStatusActive,
		GrantedBy:  grantedBy,
		GrantedAt:  time.Now(),
		ExpiresAt:  expiresAt,
		Conditions: conditions,
	}

	if err := r.CreateGrant(ctx, grant); err != nil {
		return nil, err
	}

	return r.GetGrantByID(ctx, grant.ID)
}

// RevokeAccess revokes an access grant
func (r *accessRepository) RevokeAccess(ctx context.Context, grantID, revokedBy uint) error {
	grant, err := r.GetGrantByID(ctx, grantID)
	if err != nil {
		return err
	}

	grant.Revoke(revokedBy)
	return r.UpdateGrant(ctx, grant)
}

// RevokeUserAccess revokes user access to a server
func (r *accessRepository) RevokeUserAccess(ctx context.Context, userID, serverID uint) error {
	return r.db.WithContext(ctx).
		Model(&entities.AccessGrant{}).
		Where("user_id = ? AND server_id = ? AND status = ?", userID, serverID, entities.AccessStatusActive).
		Updates(map[string]interface{}{
			"status":     entities.AccessStatusRevoked,
			"revoked_at": time.Now(),
		}).Error
}

// RevokeGroupAccess revokes group access to a server
func (r *accessRepository) RevokeGroupAccess(ctx context.Context, groupID, serverID uint) error {
	return r.db.WithContext(ctx).
		Model(&entities.AccessGrant{}).
		Where("group_id = ? AND server_id = ? AND status = ?", groupID, serverID, entities.AccessStatusActive).
		Updates(map[string]interface{}{
			"status":     entities.AccessStatusRevoked,
			"revoked_at": time.Now(),
		}).Error
}

// RevokeProjectAccess revokes project access to a server
func (r *accessRepository) RevokeProjectAccess(ctx context.Context, projectID, serverID uint) error {
	return r.db.WithContext(ctx).
		Model(&entities.AccessGrant{}).
		Where("project_id = ? AND server_id = ? AND status = ?", projectID, serverID, entities.AccessStatusActive).
		Updates(map[string]interface{}{
			"status":     entities.AccessStatusRevoked,
			"revoked_at": time.Now(),
		}).Error
}

// GetUserAccess retrieves access grants for a user
func (r *accessRepository) GetUserAccess(ctx context.Context, userID uint) ([]entities.AccessGrant, error) {
	var grants []entities.AccessGrant
	if err := r.db.WithContext(ctx).
		Preload("Server").
		Where("user_id = ?", userID).
		Find(&grants).Error; err != nil {
		return nil, fmt.Errorf("failed to get user access: %w", err)
	}
	return grants, nil
}

// GetUserServerAccess retrieves user access to a specific server
func (r *accessRepository) GetUserServerAccess(ctx context.Context, userID, serverID uint) (*entities.AccessGrant, error) {
	var grant entities.AccessGrant
	if err := r.db.WithContext(ctx).
		Preload("Server").
		Where("user_id = ? AND server_id = ? AND status = ?", userID, serverID, entities.AccessStatusActive).
		First(&grant).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, entities.ErrAccessNotFound
		}
		return nil, fmt.Errorf("failed to get user server access: %w", err)
	}
	return &grant, nil
}

// GetGroupAccess retrieves access grants for a group
func (r *accessRepository) GetGroupAccess(ctx context.Context, groupID uint) ([]entities.AccessGrant, error) {
	var grants []entities.AccessGrant
	if err := r.db.WithContext(ctx).
		Preload("Server").
		Where("group_id = ?", groupID).
		Find(&grants).Error; err != nil {
		return nil, fmt.Errorf("failed to get group access: %w", err)
	}
	return grants, nil
}

// GetProjectAccess retrieves access grants for a project
func (r *accessRepository) GetProjectAccess(ctx context.Context, projectID uint) ([]entities.AccessGrant, error) {
	var grants []entities.AccessGrant
	if err := r.db.WithContext(ctx).
		Preload("Server").
		Where("project_id = ?", projectID).
		Find(&grants).Error; err != nil {
		return nil, fmt.Errorf("failed to get project access: %w", err)
	}
	return grants, nil
}

// GetServerAccess retrieves access grants for a server
func (r *accessRepository) GetServerAccess(ctx context.Context, serverID uint) ([]entities.AccessGrant, error) {
	var grants []entities.AccessGrant
	if err := r.db.WithContext(ctx).
		Preload("User").
		Preload("Group").
		Preload("Project").
		Where("server_id = ?", serverID).
		Find(&grants).Error; err != nil {
		return nil, fmt.Errorf("failed to get server access: %w", err)
	}
	return grants, nil
}

// GetActiveGrants retrieves active access grants for a server
func (r *accessRepository) GetActiveGrants(ctx context.Context, serverID uint) ([]entities.AccessGrant, error) {
	var grants []entities.AccessGrant
	if err := r.db.WithContext(ctx).
		Preload("User").
		Preload("Group").
		Preload("Project").
		Where("server_id = ? AND status = ? AND (expires_at IS NULL OR expires_at > ?)",
			serverID, entities.AccessStatusActive, time.Now()).
		Find(&grants).Error; err != nil {
		return nil, fmt.Errorf("failed to get active grants: %w", err)
	}
	return grants, nil
}

// GetExpiredGrants retrieves expired access grants
func (r *accessRepository) GetExpiredGrants(ctx context.Context) ([]entities.AccessGrant, error) {
	var grants []entities.AccessGrant
	if err := r.db.WithContext(ctx).
		Where("expires_at IS NOT NULL AND expires_at <= ? AND status = ?",
			time.Now(), entities.AccessStatusActive).
		Find(&grants).Error; err != nil {
		return nil, fmt.Errorf("failed to get expired grants: %w", err)
	}
	return grants, nil
}

// GetExpiringGrants retrieves grants expiring before the specified time
func (r *accessRepository) GetExpiringGrants(ctx context.Context, beforeTime time.Time) ([]entities.AccessGrant, error) {
	var grants []entities.AccessGrant
	if err := r.db.WithContext(ctx).
		Preload("User").
		Preload("Server").
		Where("expires_at IS NOT NULL AND expires_at <= ? AND expires_at > ? AND status = ?",
			beforeTime, time.Now(), entities.AccessStatusActive).
		Find(&grants).Error; err != nil {
		return nil, fmt.Errorf("failed to get expiring grants: %w", err)
	}
	return grants, nil
}

// GetUserEffectiveAccess retrieves user's effective access including group and project access
func (r *accessRepository) GetUserEffectiveAccess(ctx context.Context, userID uint) ([]repositories.EffectiveAccess, error) {
	// This is a complex query that would need to join user access, group access, and project access
	// For now, returning simplified version
	var effectiveAccess []repositories.EffectiveAccess

	// Direct user access
	userGrants, err := r.GetUserAccess(ctx, userID)
	if err != nil {
		return nil, err
	}

	for _, grant := range userGrants {
		if grant.IsActive() {
			access := repositories.EffectiveAccess{
				ServerID:     grant.ServerID,
				ServerName:   grant.Server.Name,
				ServerIP:     grant.Server.IP,
				HighestRole:  grant.Role,
				DirectAccess: &grant,
				IsActive:     true,
				ExpiresAt:    grant.ExpiresAt,
				Conditions:   grant.Conditions,
			}
			effectiveAccess = append(effectiveAccess, access)
		}
	}

	// TODO: Add group and project access aggregation

	return effectiveAccess, nil
}

// GetUserEffectiveServerAccess retrieves user's effective access to a specific server
func (r *accessRepository) GetUserEffectiveServerAccess(ctx context.Context, userID, serverID uint) (*repositories.EffectiveAccess, error) {
	// Check direct access first
	directGrant, err := r.GetUserServerAccess(ctx, userID, serverID)
	if err == nil && directGrant.IsActive() {
		return &repositories.EffectiveAccess{
			ServerID:     directGrant.ServerID,
			ServerName:   directGrant.Server.Name,
			ServerIP:     directGrant.Server.IP,
			HighestRole:  directGrant.Role,
			DirectAccess: directGrant,
			IsActive:     true,
			ExpiresAt:    directGrant.ExpiresAt,
			Conditions:   directGrant.Conditions,
		}, nil
	}

	// TODO: Check group and project access

	return nil, entities.ErrAccessNotFound
}

// CheckUserServerAccess checks if user has access to a server
func (r *accessRepository) CheckUserServerAccess(ctx context.Context, userID, serverID uint) (bool, error) {
	effectiveAccess, err := r.GetUserEffectiveServerAccess(ctx, userID, serverID)
	if err != nil {
		return false, nil // No access, not an error
	}
	return effectiveAccess.IsActive, nil
}

// ApproveRequest approves an access request
func (r *accessRepository) ApproveRequest(ctx context.Context, requestID, approvedBy uint) error {
	request, err := r.GetRequestByID(ctx, requestID)
	if err != nil {
		return err
	}

	request.Approve(approvedBy)
	return r.UpdateRequest(ctx, request)
}

// RejectRequest rejects an access request
func (r *accessRepository) RejectRequest(ctx context.Context, requestID, rejectedBy uint, reason string) error {
	request, err := r.GetRequestByID(ctx, requestID)
	if err != nil {
		return err
	}

	request.Reject(rejectedBy, reason)
	return r.UpdateRequest(ctx, request)
}

// GetPendingRequests retrieves pending access requests
func (r *accessRepository) GetPendingRequests(ctx context.Context, approverID uint) ([]entities.AccessRequest, error) {
	var requests []entities.AccessRequest
	if err := r.db.WithContext(ctx).
		Preload("Requester").
		Preload("Server").
		Where("status = ? AND expires_at > ?", entities.RequestStatusPending, time.Now()).
		Find(&requests).Error; err != nil {
		return nil, fmt.Errorf("failed to get pending requests: %w", err)
	}
	return requests, nil
}

// GetUserRequests retrieves access requests for a user
func (r *accessRepository) GetUserRequests(ctx context.Context, userID uint) ([]entities.AccessRequest, error) {
	var requests []entities.AccessRequest
	if err := r.db.WithContext(ctx).
		Preload("Server").
		Where("requester_id = ?", userID).
		Find(&requests).Error; err != nil {
		return nil, fmt.Errorf("failed to get user requests: %w", err)
	}
	return requests, nil
}

// GetServerRequests retrieves access requests for a server
func (r *accessRepository) GetServerRequests(ctx context.Context, serverID uint) ([]entities.AccessRequest, error) {
	var requests []entities.AccessRequest
	if err := r.db.WithContext(ctx).
		Preload("Requester").
		Where("server_id = ?", serverID).
		Find(&requests).Error; err != nil {
		return nil, fmt.Errorf("failed to get server requests: %w", err)
	}
	return requests, nil
}

// GetExpiredRequests retrieves expired access requests
func (r *accessRepository) GetExpiredRequests(ctx context.Context) ([]entities.AccessRequest, error) {
	var requests []entities.AccessRequest
	if err := r.db.WithContext(ctx).
		Where("expires_at <= ? AND status = ?", time.Now(), entities.RequestStatusPending).
		Find(&requests).Error; err != nil {
		return nil, fmt.Errorf("failed to get expired requests: %w", err)
	}
	return requests, nil
}

// Session management methods (simplified implementations)

func (r *accessRepository) CreateSession(ctx context.Context, session *repositories.AccessSession) error {
	return r.db.WithContext(ctx).Create(session).Error
}

func (r *accessRepository) GetActiveSession(ctx context.Context, userID, serverID uint) (*repositories.AccessSession, error) {
	var session repositories.AccessSession
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND server_id = ? AND is_active = ?", userID, serverID, true).
		First(&session).Error
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (r *accessRepository) GetUserActiveSessions(ctx context.Context, userID uint) ([]repositories.AccessSession, error) {
	var sessions []repositories.AccessSession
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND is_active = ?", userID, true).
		Find(&sessions).Error
	return sessions, err
}

func (r *accessRepository) GetServerActiveSessions(ctx context.Context, serverID uint) ([]repositories.AccessSession, error) {
	var sessions []repositories.AccessSession
	err := r.db.WithContext(ctx).
		Where("server_id = ? AND is_active = ?", serverID, true).
		Find(&sessions).Error
	return sessions, err
}

func (r *accessRepository) UpdateSessionActivity(ctx context.Context, sessionID string, lastActivity time.Time) error {
	return r.db.WithContext(ctx).
		Model(&repositories.AccessSession{}).
		Where("id = ?", sessionID).
		Update("last_activity", lastActivity).Error
}

func (r *accessRepository) CloseSession(ctx context.Context, sessionID string) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&repositories.AccessSession{}).
		Where("id = ?", sessionID).
		Updates(map[string]interface{}{
			"is_active": false,
			"ended_at":  &now,
		}).Error
}

func (r *accessRepository) GetExpiredSessions(ctx context.Context) ([]repositories.AccessSession, error) {
	var sessions []repositories.AccessSession
	// Sessions inactive for more than 1 hour
	cutoff := time.Now().Add(-time.Hour)
	err := r.db.WithContext(ctx).
		Where("is_active = ? AND last_activity < ?", true, cutoff).
		Find(&sessions).Error
	return sessions, err
}

// Usage tracking methods (simplified implementations)

func (r *accessRepository) IncrementUsage(ctx context.Context, grantID uint) error {
	return r.db.WithContext(ctx).
		Model(&entities.AccessGrant{}).
		Where("id = ?", grantID).
		UpdateColumn("usage_count", gorm.Expr("usage_count + 1")).Error
}

func (r *accessRepository) UpdateLastUsed(ctx context.Context, grantID uint) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&entities.AccessGrant{}).
		Where("id = ?", grantID).
		Update("last_used_at", &now).Error
}

func (r *accessRepository) GetAccessUsageStats(ctx context.Context, grantID uint) (*repositories.AccessUsageStats, error) {
	// Simplified implementation
	return &repositories.AccessUsageStats{
		GrantID:     grantID,
		TotalUsages: 0,
		UsageByDay:  []repositories.DailyUsage{},
	}, nil
}

// Statistics methods (simplified implementations)

func (r *accessRepository) GetAccessStats(ctx context.Context) (*repositories.AccessStats, error) {
	stats := &repositories.AccessStats{}

	r.db.WithContext(ctx).Model(&entities.AccessGrant{}).Count(&stats.TotalGrants)
	r.db.WithContext(ctx).Model(&entities.AccessGrant{}).Where("status = ?", entities.AccessStatusActive).Count(&stats.ActiveGrants)
	r.db.WithContext(ctx).Model(&entities.AccessGrant{}).Where("status = ?", entities.AccessStatusRevoked).Count(&stats.RevokedGrants)
	r.db.WithContext(ctx).Model(&entities.AccessRequest{}).Count(&stats.TotalRequests)
	r.db.WithContext(ctx).Model(&entities.AccessRequest{}).Where("status = ?", entities.RequestStatusPending).Count(&stats.PendingRequests)

	return stats, nil
}

func (r *accessRepository) GetUserAccessStats(ctx context.Context, userID uint) (*repositories.UserAccessStats, error) {
	stats := &repositories.UserAccessStats{
		UserID: userID,
	}

	r.db.WithContext(ctx).Model(&entities.AccessGrant{}).Where("user_id = ?", userID).Count(&stats.TotalGrants)
	r.db.WithContext(ctx).Model(&entities.AccessGrant{}).
		Where("user_id = ? AND status = ?", userID, entities.AccessStatusActive).Count(&stats.ActiveGrants)

	return stats, nil
}

func (r *accessRepository) GetServerAccessStats(ctx context.Context, serverID uint) (*repositories.ServerAccessStats, error) {
	stats := &repositories.ServerAccessStats{
		ServerID: serverID,
	}

	r.db.WithContext(ctx).Model(&entities.AccessGrant{}).Where("server_id = ?", serverID).Count(&stats.TotalGrants)
	r.db.WithContext(ctx).Model(&entities.AccessGrant{}).
		Where("server_id = ? AND status = ?", serverID, entities.AccessStatusActive).Count(&stats.ActiveGrants)

	return stats, nil
}

func (r *accessRepository) GetAccessTrends(ctx context.Context, days int) ([]repositories.AccessTrend, error) {
	// Simplified implementation
	return []repositories.AccessTrend{}, nil
}

// Cleanup methods

func (r *accessRepository) CleanupExpiredGrants(ctx context.Context) (int64, error) {
	result := r.db.WithContext(ctx).
		Model(&entities.AccessGrant{}).
		Where("expires_at IS NOT NULL AND expires_at <= ? AND status = ?",
			time.Now(), entities.AccessStatusActive).
		Update("status", entities.AccessStatusExpired)
	return result.RowsAffected, result.Error
}

func (r *accessRepository) CleanupExpiredRequests(ctx context.Context) (int64, error) {
	result := r.db.WithContext(ctx).
		Model(&entities.AccessRequest{}).
		Where("expires_at <= ? AND status = ?", time.Now(), entities.RequestStatusPending).
		Update("status", entities.RequestStatusExpired)
	return result.RowsAffected, result.Error
}

func (r *accessRepository) CleanupInactiveSessions(ctx context.Context, timeout time.Duration) (int64, error) {
	cutoff := time.Now().Add(-timeout)
	result := r.db.WithContext(ctx).
		Model(&repositories.AccessSession{}).
		Where("is_active = ? AND last_activity < ?", true, cutoff).
		Update("is_active", false)
	return result.RowsAffected, result.Error
}

// Bulk operations (simplified implementations)

func (r *accessRepository) BulkGrantAccess(ctx context.Context, grants []entities.AccessGrant) error {
	return r.db.WithContext(ctx).CreateInBatches(grants, 100).Error
}

func (r *accessRepository) BulkRevokeAccess(ctx context.Context, grantIDs []uint, revokedBy uint) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&entities.AccessGrant{}).
		Where("id IN ?", grantIDs).
		Updates(map[string]interface{}{
			"status":     entities.AccessStatusRevoked,
			"revoked_by": revokedBy,
			"revoked_at": &now,
		}).Error
}

func (r *accessRepository) BulkApproveRequests(ctx context.Context, requestIDs []uint, approvedBy uint) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&entities.AccessRequest{}).
		Where("id IN ?", requestIDs).
		Updates(map[string]interface{}{
			"status":      entities.RequestStatusApproved,
			"approved_by": approvedBy,
			"approved_at": &now,
		}).Error
}

func (r *accessRepository) BulkRejectRequests(ctx context.Context, requestIDs []uint, rejectedBy uint, reason string) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&entities.AccessRequest{}).
		Where("id IN ?", requestIDs).
		Updates(map[string]interface{}{
			"status":           entities.RequestStatusRejected,
			"rejected_by":      rejectedBy,
			"rejected_at":      &now,
			"rejection_reason": reason,
		}).Error
}

// Helper methods

func (r *accessRepository) applyAccessGrantFilters(query *gorm.DB, filter repositories.AccessGrantFilter) *gorm.DB {
	if filter.UserID != nil {
		query = query.Where("user_id = ?", *filter.UserID)
	}
	if filter.GroupID != nil {
		query = query.Where("group_id = ?", *filter.GroupID)
	}
	if filter.ProjectID != nil {
		query = query.Where("project_id = ?", *filter.ProjectID)
	}
	if filter.ServerID != nil {
		query = query.Where("server_id = ?", *filter.ServerID)
	}
	if filter.Role != "" {
		query = query.Where("role = ?", filter.Role)
	}
	if filter.Status != "" {
		query = query.Where("status = ?", filter.Status)
	}
	if filter.GrantedBy != nil {
		query = query.Where("granted_by = ?", *filter.GrantedBy)
	}
	if filter.IsExpired != nil {
		if *filter.IsExpired {
			query = query.Where("expires_at IS NOT NULL AND expires_at <= ?", time.Now())
		} else {
			query = query.Where("expires_at IS NULL OR expires_at > ?", time.Now())
		}
	}
	if filter.IsActive != nil {
		if *filter.IsActive {
			query = query.Where("status = ? AND (expires_at IS NULL OR expires_at > ?)",
				entities.AccessStatusActive, time.Now())
		} else {
			query = query.Where("status != ? OR (expires_at IS NOT NULL AND expires_at <= ?)",
				entities.AccessStatusActive, time.Now())
		}
	}
	return query
}

func (r *accessRepository) applyAccessRequestFilters(query *gorm.DB, filter repositories.AccessRequestFilter) *gorm.DB {
	if filter.RequesterID != nil {
		query = query.Where("requester_id = ?", *filter.RequesterID)
	}
	if filter.ServerID != nil {
		query = query.Where("server_id = ?", *filter.ServerID)
	}
	if filter.Role != "" {
		query = query.Where("role = ?", filter.Role)
	}
	if filter.Status != "" {
		query = query.Where("status = ?", filter.Status)
	}
	if filter.ApprovedBy != nil {
		query = query.Where("approved_by = ?", *filter.ApprovedBy)
	}
	if filter.RejectedBy != nil {
		query = query.Where("rejected_by = ?", *filter.RejectedBy)
	}
	return query
}

func (r *accessRepository) applyPaginationAndSorting(query *gorm.DB, pagination repositories.PaginationParams, sortBy, sortOrder string) *gorm.DB {
	// Apply sorting
	if sortBy != "" {
		order := "ASC"
		if sortOrder == "desc" {
			order = "DESC"
		}
		query = query.Order(fmt.Sprintf("%s %s", sortBy, order))
	} else {
		query = query.Order("created_at DESC")
	}

	// Apply pagination
	if pagination.Limit > 0 {
		query = query.Offset(pagination.Offset).Limit(pagination.Limit)
	}

	return query
}
