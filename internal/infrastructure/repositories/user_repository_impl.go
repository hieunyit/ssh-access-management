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

type userRepository struct {
	db *gorm.DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *gorm.DB) repositories.UserRepository {
	return &userRepository{db: db}
}

// Create creates a new user
func (r *userRepository) Create(ctx context.Context, user *entities.User) error {
	if err := r.db.WithContext(ctx).Create(user).Error; err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return entities.ErrUserAlreadyExists
		}
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

// GetByID retrieves a user by ID
func (r *userRepository) GetByID(ctx context.Context, id uint) (*entities.User, error) {
	var user entities.User
	if err := r.db.WithContext(ctx).
		Preload("SSHKeys").
		Preload("Groups").
		Preload("Projects").
		First(&user, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, entities.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user, nil
}

// GetByUsername retrieves a user by username
func (r *userRepository) GetByUsername(ctx context.Context, username string) (*entities.User, error) {
	var user entities.User
	if err := r.db.WithContext(ctx).
		Preload("SSHKeys").
		Preload("Groups").
		Preload("Projects").
		Where("username = ?", username).
		First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, entities.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}
	return &user, nil
}

// GetByEmail retrieves a user by email
func (r *userRepository) GetByEmail(ctx context.Context, email string) (*entities.User, error) {
	var user entities.User
	if err := r.db.WithContext(ctx).
		Preload("SSHKeys").
		Preload("Groups").
		Preload("Projects").
		Where("email = ?", email).
		First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, entities.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}
	return &user, nil
}

// Update updates a user
func (r *userRepository) Update(ctx context.Context, user *entities.User) error {
	if err := r.db.WithContext(ctx).Save(user).Error; err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return entities.ErrUserAlreadyExists
		}
		return fmt.Errorf("failed to update user: %w", err)
	}
	return nil
}

// Delete soft deletes a user
func (r *userRepository) Delete(ctx context.Context, id uint) error {
	if err := r.db.WithContext(ctx).Delete(&entities.User{}, id).Error; err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}

// List retrieves users with filtering and pagination
func (r *userRepository) List(ctx context.Context, filter repositories.UserFilter) ([]entities.User, *repositories.PaginationResult, error) {
	var users []entities.User
	var total int64

	query := r.db.WithContext(ctx).Model(&entities.User{})

	// Apply filters
	query = r.applyUserFilters(query, filter)

	// Count total records
	if err := query.Count(&total).Error; err != nil {
		return nil, nil, fmt.Errorf("failed to count users: %w", err)
	}

	// Apply pagination and sorting
	query = r.applyPaginationAndSorting(query, filter.Pagination, filter.SortBy, filter.SortOrder)

	// Preload associations
	query = query.Preload("SSHKeys").Preload("Groups").Preload("Projects")

	if err := query.Find(&users).Error; err != nil {
		return nil, nil, fmt.Errorf("failed to list users: %w", err)
	}

	pagination := repositories.NewPaginationResult(filter.Pagination.Page, filter.Pagination.PageSize, total)
	return users, pagination, nil
}

// Activate activates a user
func (r *userRepository) Activate(ctx context.Context, id uint) error {
	if err := r.db.WithContext(ctx).
		Model(&entities.User{}).
		Where("id = ?", id).
		Update("status", entities.StatusActive).Error; err != nil {
		return fmt.Errorf("failed to activate user: %w", err)
	}
	return nil
}

// Deactivate deactivates a user
func (r *userRepository) Deactivate(ctx context.Context, id uint) error {
	if err := r.db.WithContext(ctx).
		Model(&entities.User{}).
		Where("id = ?", id).
		Update("status", entities.StatusInactive).Error; err != nil {
		return fmt.Errorf("failed to deactivate user: %w", err)
	}
	return nil
}

// Ban bans a user
func (r *userRepository) Ban(ctx context.Context, id uint) error {
	if err := r.db.WithContext(ctx).
		Model(&entities.User{}).
		Where("id = ?", id).
		Update("status", entities.StatusBanned).Error; err != nil {
		return fmt.Errorf("failed to ban user: %w", err)
	}
	return nil
}

// ValidateCredentials validates user credentials
func (r *userRepository) ValidateCredentials(ctx context.Context, username, password string) (*entities.User, error) {
	var user entities.User
	if err := r.db.WithContext(ctx).
		Where("username = ? OR email = ?", username, username).
		First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, entities.ErrInvalidUserCredentials
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	// Note: Password validation should be done in the service layer
	return &user, nil
}

// UpdatePassword updates user password
func (r *userRepository) UpdatePassword(ctx context.Context, id uint, hashedPassword string) error {
	if err := r.db.WithContext(ctx).
		Model(&entities.User{}).
		Where("id = ?", id).
		Update("password", hashedPassword).Error; err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}
	return nil
}

// UpdateLastLogin updates user's last login timestamp
func (r *userRepository) UpdateLastLogin(ctx context.Context, id uint) error {
	now := time.Now()
	if err := r.db.WithContext(ctx).
		Model(&entities.User{}).
		Where("id = ?", id).
		Update("last_login_at", &now).Error; err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}
	return nil
}

// GetUserGroups retrieves groups for a user
func (r *userRepository) GetUserGroups(ctx context.Context, userID uint) ([]entities.Group, error) {
	var groups []entities.Group
	if err := r.db.WithContext(ctx).
		Joins("JOIN user_groups ON user_groups.group_id = groups.id").
		Where("user_groups.user_id = ?", userID).
		Find(&groups).Error; err != nil {
		return nil, fmt.Errorf("failed to get user groups: %w", err)
	}
	return groups, nil
}

// GetUserProjects retrieves projects for a user
func (r *userRepository) GetUserProjects(ctx context.Context, userID uint) ([]entities.Project, error) {
	var projects []entities.Project
	if err := r.db.WithContext(ctx).
		Joins("JOIN user_projects ON user_projects.project_id = projects.id").
		Where("user_projects.user_id = ?", userID).
		Find(&projects).Error; err != nil {
		return nil, fmt.Errorf("failed to get user projects: %w", err)
	}
	return projects, nil
}

// AddToGroup adds user to a group
func (r *userRepository) AddToGroup(ctx context.Context, userID, groupID uint) error {
	user := entities.User{ID: userID}
	group := entities.Group{ID: groupID}

	if err := r.db.WithContext(ctx).Model(&user).Association("Groups").Append(&group); err != nil {
		return fmt.Errorf("failed to add user to group: %w", err)
	}
	return nil
}

// RemoveFromGroup removes user from a group
func (r *userRepository) RemoveFromGroup(ctx context.Context, userID, groupID uint) error {
	user := entities.User{ID: userID}
	group := entities.Group{ID: groupID}

	if err := r.db.WithContext(ctx).Model(&user).Association("Groups").Delete(&group); err != nil {
		return fmt.Errorf("failed to remove user from group: %w", err)
	}
	return nil
}

// AddToProject adds user to a project
func (r *userRepository) AddToProject(ctx context.Context, userID, projectID uint) error {
	user := entities.User{ID: userID}
	project := entities.Project{ID: projectID}

	if err := r.db.WithContext(ctx).Model(&user).Association("Projects").Append(&project); err != nil {
		return fmt.Errorf("failed to add user to project: %w", err)
	}
	return nil
}

// RemoveFromProject removes user from a project
func (r *userRepository) RemoveFromProject(ctx context.Context, userID, projectID uint) error {
	user := entities.User{ID: userID}
	project := entities.Project{ID: projectID}

	if err := r.db.WithContext(ctx).Model(&user).Association("Projects").Delete(&project); err != nil {
		return fmt.Errorf("failed to remove user from project: %w", err)
	}
	return nil
}

// CreateSSHKey creates a new SSH key for user
func (r *userRepository) CreateSSHKey(ctx context.Context, sshKey *entities.SSHKey) error {
	if err := r.db.WithContext(ctx).Create(sshKey).Error; err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return entities.ErrSSHKeyAlreadyExists
		}
		return fmt.Errorf("failed to create SSH key: %w", err)
	}
	return nil
}

// GetSSHKey retrieves an SSH key by ID
func (r *userRepository) GetSSHKey(ctx context.Context, id uint) (*entities.SSHKey, error) {
	var sshKey entities.SSHKey
	if err := r.db.WithContext(ctx).
		Preload("User").
		First(&sshKey, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, entities.ErrSSHKeyNotFound
		}
		return nil, fmt.Errorf("failed to get SSH key: %w", err)
	}
	return &sshKey, nil
}

// GetUserSSHKeys retrieves SSH keys for a user
func (r *userRepository) GetUserSSHKeys(ctx context.Context, userID uint) ([]entities.SSHKey, error) {
	var sshKeys []entities.SSHKey
	if err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Find(&sshKeys).Error; err != nil {
		return nil, fmt.Errorf("failed to get user SSH keys: %w", err)
	}
	return sshKeys, nil
}

// UpdateSSHKey updates an SSH key
func (r *userRepository) UpdateSSHKey(ctx context.Context, sshKey *entities.SSHKey) error {
	if err := r.db.WithContext(ctx).Save(sshKey).Error; err != nil {
		return fmt.Errorf("failed to update SSH key: %w", err)
	}
	return nil
}

// DeleteSSHKey deletes an SSH key
func (r *userRepository) DeleteSSHKey(ctx context.Context, id uint) error {
	if err := r.db.WithContext(ctx).Delete(&entities.SSHKey{}, id).Error; err != nil {
		return fmt.Errorf("failed to delete SSH key: %w", err)
	}
	return nil
}

// GetSSHKeyByFingerprint retrieves SSH key by fingerprint
func (r *userRepository) GetSSHKeyByFingerprint(ctx context.Context, fingerprint string) (*entities.SSHKey, error) {
	var sshKey entities.SSHKey
	if err := r.db.WithContext(ctx).
		Preload("User").
		Where("fingerprint = ?", fingerprint).
		First(&sshKey).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, entities.ErrSSHKeyNotFound
		}
		return nil, fmt.Errorf("failed to get SSH key by fingerprint: %w", err)
	}
	return &sshKey, nil
}

// GetUserStats retrieves user statistics
func (r *userRepository) GetUserStats(ctx context.Context, userID uint) (*repositories.UserStats, error) {
	stats := &repositories.UserStats{}

	// Get basic user info
	var user entities.User
	if err := r.db.WithContext(ctx).First(&user, userID).Error; err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Get total servers accessible (through direct access, groups, and projects)
	if err := r.db.WithContext(ctx).
		Table("access_grants").
		Where("user_id = ? AND status = ? AND (expires_at IS NULL OR expires_at > ?)",
			userID, entities.AccessStatusActive, time.Now()).
		Count(&stats.TotalServersAccess).Error; err != nil {
		return nil, fmt.Errorf("failed to count server access: %w", err)
	}

	// Get active sessions (would need session tracking table)
	// stats.ActiveSessions = 0 // TODO: Implement session tracking

	// Get last login
	if user.LastLoginAt != nil {
		lastLogin := user.LastLoginAt.Format(time.RFC3339)
		stats.LastLoginAt = &lastLogin
	}

	// Get SSH key counts
	if err := r.db.WithContext(ctx).
		Model(&entities.SSHKey{}).
		Where("user_id = ?", userID).
		Count(&stats.TotalSSHKeys).Error; err != nil {
		return nil, fmt.Errorf("failed to count SSH keys: %w", err)
	}

	if err := r.db.WithContext(ctx).
		Model(&entities.SSHKey{}).
		Where("user_id = ? AND is_active = ? AND (expires_at IS NULL OR expires_at > ?)",
			userID, true, time.Now()).
		Count(&stats.ActiveSSHKeys).Error; err != nil {
		return nil, fmt.Errorf("failed to count active SSH keys: %w", err)
	}

	// Get groups count
	if err := r.db.WithContext(ctx).
		Table("user_groups").
		Where("user_id = ?", userID).
		Count(&stats.GroupsCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count groups: %w", err)
	}

	// Get projects count
	if err := r.db.WithContext(ctx).
		Table("user_projects").
		Where("user_id = ?", userID).
		Count(&stats.ProjectsCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count projects: %w", err)
	}

	// Get access grants count
	if err := r.db.WithContext(ctx).
		Model(&entities.AccessGrant{}).
		Where("user_id = ?", userID).
		Count(&stats.AccessGrantsCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count access grants: %w", err)
	}

	// Get recent activities from audit logs
	var activities []repositories.Activity
	var auditLogs []entities.AuditLog
	if err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("timestamp DESC").
		Limit(10).
		Find(&auditLogs).Error; err != nil {
		return nil, fmt.Errorf("failed to get recent activities: %w", err)
	}

	for _, log := range auditLogs {
		activities = append(activities, repositories.Activity{
			Action:    string(log.Action),
			Resource:  string(log.Resource),
			Timestamp: log.Timestamp.Format(time.RFC3339),
			Details:   log.Details.Description,
		})
	}
	stats.RecentActivity = activities

	return stats, nil
}

// GetActiveUsersCount retrieves count of active users
func (r *userRepository) GetActiveUsersCount(ctx context.Context) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).
		Model(&entities.User{}).
		Where("status = ?", entities.StatusActive).
		Count(&count).Error; err != nil {
		return 0, fmt.Errorf("failed to count active users: %w", err)
	}
	return count, nil
}

// GetUsersByRole retrieves users by role
func (r *userRepository) GetUsersByRole(ctx context.Context, role string) ([]entities.User, error) {
	var users []entities.User
	if err := r.db.WithContext(ctx).
		Where("role = ?", role).
		Find(&users).Error; err != nil {
		return nil, fmt.Errorf("failed to get users by role: %w", err)
	}
	return users, nil
}

// BulkCreate creates multiple users
func (r *userRepository) BulkCreate(ctx context.Context, users []entities.User) error {
	if err := r.db.WithContext(ctx).CreateInBatches(users, 100).Error; err != nil {
		return fmt.Errorf("failed to bulk create users: %w", err)
	}
	return nil
}

// BulkUpdate updates multiple users
func (r *userRepository) BulkUpdate(ctx context.Context, users []entities.User) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, user := range users {
			if err := tx.Save(&user).Error; err != nil {
				return fmt.Errorf("failed to update user %d: %w", user.ID, err)
			}
		}
		return nil
	})
}

// BulkDelete deletes multiple users
func (r *userRepository) BulkDelete(ctx context.Context, ids []uint) error {
	if err := r.db.WithContext(ctx).Delete(&entities.User{}, ids).Error; err != nil {
		return fmt.Errorf("failed to bulk delete users: %w", err)
	}
	return nil
}

// Helper methods

func (r *userRepository) applyUserFilters(query *gorm.DB, filter repositories.UserFilter) *gorm.DB {
	if filter.Username != "" {
		query = query.Where("username ILIKE ?", "%"+filter.Username+"%")
	}
	if filter.Email != "" {
		query = query.Where("email ILIKE ?", "%"+filter.Email+"%")
	}
	if filter.FullName != "" {
		query = query.Where("full_name ILIKE ?", "%"+filter.FullName+"%")
	}
	if filter.Department != "" {
		query = query.Where("department = ?", filter.Department)
	}
	if filter.Role != "" {
		query = query.Where("role = ?", filter.Role)
	}
	if filter.Status != "" {
		query = query.Where("status = ?", filter.Status)
	}
	if filter.Search != "" {
		query = query.Where("username ILIKE ? OR email ILIKE ? OR full_name ILIKE ?",
			"%"+filter.Search+"%", "%"+filter.Search+"%", "%"+filter.Search+"%")
	}
	if filter.GroupID != nil {
		query = query.Joins("JOIN user_groups ON user_groups.user_id = users.id").
			Where("user_groups.group_id = ?", *filter.GroupID)
	}
	if filter.ProjectID != nil {
		query = query.Joins("JOIN user_projects ON user_projects.user_id = users.id").
			Where("user_projects.project_id = ?", *filter.ProjectID)
	}
	return query
}

func (r *userRepository) applyPaginationAndSorting(query *gorm.DB, pagination repositories.PaginationParams, sortBy, sortOrder string) *gorm.DB {
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
