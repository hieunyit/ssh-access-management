package repositories

import (
	"context"
	"ssh-access-management/internal/domain/entities"
)

// UserRepository defines user repository interface
type UserRepository interface {
	// User CRUD operations
	Create(ctx context.Context, user *entities.User) error
	GetByID(ctx context.Context, id uint) (*entities.User, error)
	GetByUsername(ctx context.Context, username string) (*entities.User, error)
	GetByEmail(ctx context.Context, email string) (*entities.User, error)
	Update(ctx context.Context, user *entities.User) error
	Delete(ctx context.Context, id uint) error
	List(ctx context.Context, filter UserFilter) ([]entities.User, *PaginationResult, error)

	// User status management
	Activate(ctx context.Context, id uint) error
	Deactivate(ctx context.Context, id uint) error
	Ban(ctx context.Context, id uint) error

	// User authentication
	ValidateCredentials(ctx context.Context, username, password string) (*entities.User, error)
	UpdatePassword(ctx context.Context, id uint, hashedPassword string) error
	UpdateLastLogin(ctx context.Context, id uint) error

	// User groups and projects
	GetUserGroups(ctx context.Context, userID uint) ([]entities.Group, error)
	GetUserProjects(ctx context.Context, userID uint) ([]entities.Project, error)
	AddToGroup(ctx context.Context, userID, groupID uint) error
	RemoveFromGroup(ctx context.Context, userID, groupID uint) error
	AddToProject(ctx context.Context, userID, projectID uint) error
	RemoveFromProject(ctx context.Context, userID, projectID uint) error

	// SSH key management
	CreateSSHKey(ctx context.Context, sshKey *entities.SSHKey) error
	GetSSHKey(ctx context.Context, id uint) (*entities.SSHKey, error)
	GetUserSSHKeys(ctx context.Context, userID uint) ([]entities.SSHKey, error)
	UpdateSSHKey(ctx context.Context, sshKey *entities.SSHKey) error
	DeleteSSHKey(ctx context.Context, id uint) error
	GetSSHKeyByFingerprint(ctx context.Context, fingerprint string) (*entities.SSHKey, error)

	// User statistics
	GetUserStats(ctx context.Context, userID uint) (*UserStats, error)
	GetActiveUsersCount(ctx context.Context) (int64, error)
	GetUsersByRole(ctx context.Context, role string) ([]entities.User, error)

	// Bulk operations
	BulkCreate(ctx context.Context, users []entities.User) error
	BulkUpdate(ctx context.Context, users []entities.User) error
	BulkDelete(ctx context.Context, ids []uint) error
}

// UserFilter represents user filtering options
type UserFilter struct {
	Username   string
	Email      string
	FullName   string
	Department string
	Role       string
	Status     string
	Search     string
	GroupID    *uint
	ProjectID  *uint
	Pagination PaginationParams
	SortBy     string
	SortOrder  string
}

// UserStats represents user statistics
type UserStats struct {
	TotalServersAccess int64      `json:"total_servers_access"`
	ActiveSessions     int64      `json:"active_sessions"`
	LastLoginAt        *string    `json:"last_login_at"`
	TotalSSHKeys       int64      `json:"total_ssh_keys"`
	ActiveSSHKeys      int64      `json:"active_ssh_keys"`
	GroupsCount        int64      `json:"groups_count"`
	ProjectsCount      int64      `json:"projects_count"`
	AccessGrantsCount  int64      `json:"access_grants_count"`
	RecentActivity     []Activity `json:"recent_activity"`
}

// Activity represents user activity
type Activity struct {
	Action    string `json:"action"`
	Resource  string `json:"resource"`
	Timestamp string `json:"timestamp"`
	Details   string `json:"details"`
}

// PaginationParams represents pagination parameters
type PaginationParams struct {
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
	Offset   int `json:"offset"`
	Limit    int `json:"limit"`
}

// PaginationResult represents pagination result
type PaginationResult struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
	HasNext    bool  `json:"has_next"`
	HasPrev    bool  `json:"has_prev"`
}

// NewPaginationParams creates new pagination parameters
func NewPaginationParams(page, pageSize int) PaginationParams {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	return PaginationParams{
		Page:     page,
		PageSize: pageSize,
		Offset:   (page - 1) * pageSize,
		Limit:    pageSize,
	}
}

// NewPaginationResult creates new pagination result
func NewPaginationResult(page, pageSize int, total int64) *PaginationResult {
	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))

	return &PaginationResult{
		Page:       page,
		PageSize:   pageSize,
		Total:      total,
		TotalPages: totalPages,
		HasNext:    page < totalPages,
		HasPrev:    page > 1,
	}
}
