package dto

import (
	"ssh-access-management/internal/domain/entities"
	"ssh-access-management/internal/domain/repositories"
	"time"
)

// CreateProjectRequest represents request to create project
type CreateProjectRequest struct {
	Name        string                   `json:"name" validate:"required,min=1,max=100"`
	Code        string                   `json:"code" validate:"required,min=2,max=20,alphanum"`
	Description string                   `json:"description,omitempty"`
	Status      entities.ProjectStatus   `json:"status,omitempty" validate:"omitempty,oneof=active inactive completed archived"`
	Priority    entities.ProjectPriority `json:"priority,omitempty" validate:"omitempty,oneof=low medium high critical"`
	StartDate   *time.Time               `json:"start_date,omitempty"`
	EndDate     *time.Time               `json:"end_date,omitempty"`
	Budget      float64                  `json:"budget,omitempty" validate:"omitempty,min=0"`
	OwnerID     uint                     `json:"owner_id" validate:"required"`
	Metadata    entities.ProjectMetadata `json:"metadata,omitempty"`
	Settings    entities.ProjectSettings `json:"settings,omitempty"`
	UserIDs     []uint                   `json:"user_ids,omitempty"`
	GroupIDs    []uint                   `json:"group_ids,omitempty"`
	ServerIDs   []uint                   `json:"server_ids,omitempty"`
}

// UpdateProjectRequest represents request to update project
type UpdateProjectRequest struct {
	Name        *string                   `json:"name,omitempty" validate:"omitempty,min=1,max=100"`
	Description *string                   `json:"description,omitempty"`
	Status      *entities.ProjectStatus   `json:"status,omitempty" validate:"omitempty,oneof=active inactive completed archived"`
	Priority    *entities.ProjectPriority `json:"priority,omitempty" validate:"omitempty,oneof=low medium high critical"`
	StartDate   *time.Time                `json:"start_date,omitempty"`
	EndDate     *time.Time                `json:"end_date,omitempty"`
	Budget      *float64                  `json:"budget,omitempty" validate:"omitempty,min=0"`
	OwnerID     *uint                     `json:"owner_id,omitempty"`
	Metadata    *entities.ProjectMetadata `json:"metadata,omitempty"`
	Settings    *entities.ProjectSettings `json:"settings,omitempty"`
}

// ListProjectsRequest represents request to list projects
type ListProjectsRequest struct {
	Name         string   `json:"name,omitempty"`
	Code         string   `json:"code,omitempty"`
	Status       string   `json:"status,omitempty"`
	Priority     string   `json:"priority,omitempty"`
	OwnerID      *uint    `json:"owner_id,omitempty"`
	Department   string   `json:"department,omitempty"`
	Environment  string   `json:"environment,omitempty"`
	Search       string   `json:"search,omitempty"`
	IsActive     *bool    `json:"is_active,omitempty"`
	IsOverdue    *bool    `json:"is_overdue,omitempty"`
	IsOverBudget *bool    `json:"is_over_budget,omitempty"`
	StartAfter   *string  `json:"start_after,omitempty"`
	StartBefore  *string  `json:"start_before,omitempty"`
	EndAfter     *string  `json:"end_after,omitempty"`
	EndBefore    *string  `json:"end_before,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	Page         int      `json:"page,omitempty"`
	PageSize     int      `json:"page_size,omitempty"`
	SortBy       string   `json:"sort_by,omitempty"`
	SortOrder    string   `json:"sort_order,omitempty"`
}

// ListProjectsResponse represents response for listing projects
type ListProjectsResponse struct {
	Projects   []entities.Project             `json:"projects"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *ProjectsSummary               `json:"summary"`
}

// ProjectDetailsResponse represents detailed project information
type ProjectDetailsResponse struct {
	Project  *entities.Project   `json:"project"`
	Owner    *ProjectOwnerInfo   `json:"owner"`
	Users    []ProjectUserInfo   `json:"users"`
	Groups   []ProjectGroupInfo  `json:"groups"`
	Servers  []ProjectServerInfo `json:"servers"`
	Stats    *ProjectStats       `json:"stats"`
	Progress *ProjectProgress    `json:"progress"`
	Timeline []ProjectMilestone  `json:"timeline"`
	Budget   *ProjectBudgetInfo  `json:"budget,omitempty"`
}

// ProjectOwnerInfo represents project owner information
type ProjectOwnerInfo struct {
	UserID     uint   `json:"user_id"`
	Username   string `json:"username"`
	FullName   string `json:"full_name"`
	Email      string `json:"email"`
	Department string `json:"department"`
	Role       string `json:"role"`
}

// ProjectUserInfo represents user information in project
type ProjectUserInfo struct {
	UserID     uint   `json:"user_id"`
	Username   string `json:"username"`
	FullName   string `json:"full_name"`
	Email      string `json:"email"`
	Role       string `json:"role"`
	Department string `json:"department"`
	JoinedAt   string `json:"joined_at"`
	IsActive   bool   `json:"is_active"`
}

// ProjectGroupInfo represents group information in project
type ProjectGroupInfo struct {
	GroupID     uint   `json:"group_id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	UserCount   int64  `json:"user_count"`
	AddedAt     string `json:"added_at"`
	IsActive    bool   `json:"is_active"`
}

// ProjectServerInfo represents server information in project
type ProjectServerInfo struct {
	ServerID    uint   `json:"server_id"`
	Name        string `json:"name"`
	IP          string `json:"ip"`
	Hostname    string `json:"hostname"`
	Environment string `json:"environment"`
	Platform    string `json:"platform"`
	Status      string `json:"status"`
	AddedAt     string `json:"added_at"`
}

// ProjectStats represents project statistics
type ProjectStats struct {
	TotalUsers        int64            `json:"total_users"`
	ActiveUsers       int64            `json:"active_users"`
	TotalGroups       int64            `json:"total_groups"`
	ActiveGroups      int64            `json:"active_groups"`
	TotalServers      int64            `json:"total_servers"`
	ActiveServers     int64            `json:"active_servers"`
	AccessGrants      int64            `json:"access_grants"`
	ActiveSessions    int64            `json:"active_sessions"`
	TotalSessions     int64            `json:"total_sessions"`
	UsersByRole       map[string]int64 `json:"users_by_role"`
	ServersByEnv      map[string]int64 `json:"servers_by_environment"`
	ServersByPlatform map[string]int64 `json:"servers_by_platform"`
	LastActivity      *string          `json:"last_activity,omitempty"`
}

// ProjectProgress represents project progress information
type ProjectProgress struct {
	Percentage          float64 `json:"percentage"`
	DaysElapsed         int     `json:"days_elapsed"`
	DaysRemaining       int     `json:"days_remaining"`
	TotalDays           int     `json:"total_days"`
	IsOnTrack           bool    `json:"is_on_track"`
	IsOverdue           bool    `json:"is_overdue"`
	CompletionDate      *string `json:"completion_date,omitempty"`
	MilestonesTotal     int     `json:"milestones_total"`
	MilestonesCompleted int     `json:"milestones_completed"`
}

// ProjectMilestone represents project milestone
type ProjectMilestone struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	DueDate      *string  `json:"due_date,omitempty"`
	CompletedAt  *string  `json:"completed_at,omitempty"`
	Status       string   `json:"status"`
	Progress     float64  `json:"progress"`
	Dependencies []string `json:"dependencies,omitempty"`
}

// ProjectBudgetInfo represents project budget information
type ProjectBudgetInfo struct {
	TotalBudget       float64 `json:"total_budget"`
	SpentAmount       float64 `json:"spent_amount"`
	RemainingAmount   float64 `json:"remaining_amount"`
	BurnRate          float64 `json:"burn_rate"`
	ProjectedTotal    float64 `json:"projected_total"`
	IsOverBudget      bool    `json:"is_over_budget"`
	BudgetUtilization float64 `json:"budget_utilization"`
}

// ProjectsSummary represents summary of projects
type ProjectsSummary struct {
	Total        int64            `json:"total"`
	Active       int64            `json:"active"`
	Inactive     int64            `json:"inactive"`
	Completed    int64            `json:"completed"`
	Archived     int64            `json:"archived"`
	Overdue      int64            `json:"overdue"`
	OverBudget   int64            `json:"over_budget"`
	ByStatus     map[string]int64 `json:"by_status"`
	ByPriority   map[string]int64 `json:"by_priority"`
	ByDepartment map[string]int64 `json:"by_department"`
}

// AddUsersToProjectRequest represents request to add users to project
type AddUsersToProjectRequest struct {
	UserIDs []uint `json:"user_ids" validate:"required,min=1,max=100"`
}

// RemoveUsersFromProjectRequest represents request to remove users from project
type RemoveUsersFromProjectRequest struct {
	UserIDs []uint `json:"user_ids" validate:"required,min=1,max=100"`
}

// AddGroupsToProjectRequest represents request to add groups to project
type AddGroupsToProjectRequest struct {
	GroupIDs []uint `json:"group_ids" validate:"required,min=1,max=50"`
}

// RemoveGroupsFromProjectRequest represents request to remove groups from project
type RemoveGroupsFromProjectRequest struct {
	GroupIDs []uint `json:"group_ids" validate:"required,min=1,max=50"`
}

// AddServersToProjectRequest represents request to add servers to project
type AddServersToProjectRequest struct {
	ServerIDs []uint `json:"server_ids" validate:"required,min=1,max=100"`
}

// RemoveServersFromProjectRequest represents request to remove servers from project
type RemoveServersFromProjectRequest struct {
	ServerIDs []uint `json:"server_ids" validate:"required,min=1,max=100"`
}

// ProjectSearchFilters represents project search filters
type ProjectSearchFilters struct {
	Status       string   `json:"status,omitempty"`
	Priority     string   `json:"priority,omitempty"`
	Department   string   `json:"department,omitempty"`
	Environment  string   `json:"environment,omitempty"`
	HasBudget    *bool    `json:"has_budget,omitempty"`
	IsOverdue    *bool    `json:"is_overdue,omitempty"`
	IsOverBudget *bool    `json:"is_over_budget,omitempty"`
	MinBudget    *float64 `json:"min_budget,omitempty"`
	MaxBudget    *float64 `json:"max_budget,omitempty"`
	MinUsers     *int     `json:"min_users,omitempty"`
	MaxUsers     *int     `json:"max_users,omitempty"`
	MinServers   *int     `json:"min_servers,omitempty"`
	MaxServers   *int     `json:"max_servers,omitempty"`
	Tags         []string `json:"tags,omitempty"`
}

// BulkCreateProjectsRequest represents bulk project creation request
type BulkCreateProjectsRequest struct {
	Projects []CreateProjectRequest `json:"projects" validate:"required,min=1,max=20"`
}

// BulkUpdateProjectsRequest represents bulk project update request
type BulkUpdateProjectsRequest struct {
	Updates []ProjectUpdateItem `json:"updates" validate:"required,min=1,max=50"`
}

// ProjectUpdateItem represents single project update in bulk operation
type ProjectUpdateItem struct {
	ID   uint                 `json:"id" validate:"required"`
	Data UpdateProjectRequest `json:"data"`
}

// ProjectActivity represents project activity information
type ProjectActivity struct {
	ProjectID     uint                   `json:"project_id"`
	ProjectName   string                 `json:"project_name"`
	TimeRange     repositories.TimeRange `json:"time_range"`
	UserActivity  []UserActivitySummary  `json:"user_activity"`
	ServerAccess  []ServerAccessSummary  `json:"server_access"`
	RecentChanges []ProjectChange        `json:"recent_changes"`
	Stats         *ProjectActivityStats  `json:"stats"`
}

// ProjectChange represents a change in project
type ProjectChange struct {
	Type        string            `json:"type"`
	Action      string            `json:"action"`
	Description string            `json:"description"`
	UserID      *uint             `json:"user_id,omitempty"`
	Username    string            `json:"username,omitempty"`
	Timestamp   string            `json:"timestamp"`
	Details     map[string]string `json:"details,omitempty"`
}

// ProjectActivityStats represents project activity statistics
type ProjectActivityStats struct {
	TotalActions     int64 `json:"total_actions"`
	TotalConnections int64 `json:"total_connections"`
	ActiveUsers      int64 `json:"active_users"`
	ActiveServers    int64 `json:"active_servers"`
	NewMembers       int64 `json:"new_members"`
	RemovedMembers   int64 `json:"removed_members"`
	BudgetChanges    int64 `json:"budget_changes"`
	StatusChanges    int64 `json:"status_changes"`
}

// ProjectReportRequest represents project report request
type ProjectReportRequest struct {
	ProjectIDs    []uint  `json:"project_ids,omitempty"`
	StartDate     *string `json:"start_date,omitempty"`
	EndDate       *string `json:"end_date,omitempty"`
	ReportType    string  `json:"report_type" validate:"required,oneof=summary detailed budget activity"`
	Format        string  `json:"format" validate:"required,oneof=json csv xlsx pdf"`
	IncludeBudget bool    `json:"include_budget,omitempty"`
	IncludeStats  bool    `json:"include_stats,omitempty"`
	GroupBy       string  `json:"group_by,omitempty" validate:"omitempty,oneof=status priority department owner"`
}

// ProjectDashboardData represents project dashboard data
type ProjectDashboardData struct {
	Summary        *ProjectsSummary     `json:"summary"`
	TopProjects    []ProjectSummaryItem `json:"top_projects"`
	RecentActivity []ProjectChange      `json:"recent_activity"`
	BudgetSummary  *BudgetSummary       `json:"budget_summary"`
	Alerts         []ProjectAlert       `json:"alerts"`
	Charts         []ChartData          `json:"charts"`
	UpdatedAt      string               `json:"updated_at"`
}

// ProjectSummaryItem represents project summary item
type ProjectSummaryItem struct {
	ProjectID   uint    `json:"project_id"`
	Name        string  `json:"name"`
	Code        string  `json:"code"`
	Status      string  `json:"status"`
	Priority    string  `json:"priority"`
	Progress    float64 `json:"progress"`
	Budget      float64 `json:"budget"`
	Spent       float64 `json:"spent"`
	UserCount   int64   `json:"user_count"`
	ServerCount int64   `json:"server_count"`
}

// BudgetSummary represents budget summary
type BudgetSummary struct {
	TotalBudget      float64 `json:"total_budget"`
	TotalSpent       float64 `json:"total_spent"`
	TotalRemaining   float64 `json:"total_remaining"`
	OverBudgetCount  int64   `json:"over_budget_count"`
	UnderBudgetCount int64   `json:"under_budget_count"`
	AverageBurnRate  float64 `json:"average_burn_rate"`
}

// ProjectAlert represents project alert
type ProjectAlert struct {
	ProjectID   uint   `json:"project_id"`
	ProjectName string `json:"project_name"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Message     string `json:"message"`
	CreatedAt   string `json:"created_at"`
}

// ProjectMembersResponse represents project members response
type ProjectMembersResponse struct {
	Users      []ProjectUserInfo              `json:"users"`
	Groups     []ProjectGroupInfo             `json:"groups"`
	Servers    []ProjectServerInfo            `json:"servers"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *ProjectMembersSummary         `json:"summary"`
}

// ProjectMembersSummary represents summary of project members
type ProjectMembersSummary struct {
	TotalUsers    int64            `json:"total_users"`
	TotalGroups   int64            `json:"total_groups"`
	TotalServers  int64            `json:"total_servers"`
	UsersByRole   map[string]int64 `json:"users_by_role"`
	UsersByStatus map[string]int64 `json:"users_by_status"`
}
