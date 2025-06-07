package services

import (
	"context"
	"ssh-access-management/internal/domain/entities"
	"ssh-access-management/internal/domain/repositories"
	"time"
)

// ProjectService defines project service interface
type ProjectService interface {
	// Project Management
	CreateProject(ctx context.Context, req CreateProjectRequest) (*entities.Project, error)
	GetProject(ctx context.Context, id uint) (*entities.Project, error)
	GetProjectByName(ctx context.Context, name string) (*entities.Project, error)
	GetProjectByCode(ctx context.Context, code string) (*entities.Project, error)
	UpdateProject(ctx context.Context, id uint, req UpdateProjectRequest) (*entities.Project, error)
	DeleteProject(ctx context.Context, id uint) error
	ListProjects(ctx context.Context, req ListProjectsRequest) (*ListProjectsResponse, error)

	// Project Status Management
	UpdateProjectStatus(ctx context.Context, id uint, status entities.ProjectStatus) error
	ActivateProject(ctx context.Context, id uint) error
	DeactivateProject(ctx context.Context, id uint) error
	CompleteProject(ctx context.Context, id uint, completionNotes string) error
	ArchiveProject(ctx context.Context, id uint, reason string) error
	RestoreProject(ctx context.Context, id uint) error

	// User Management
	AddUserToProject(ctx context.Context, projectID, userID uint, role string) error
	RemoveUserFromProject(ctx context.Context, projectID, userID uint) error
	GetProjectUsers(ctx context.Context, projectID uint) ([]entities.User, error)
	GetUserProjects(ctx context.Context, userID uint) ([]entities.Project, error)
	IsUserInProject(ctx context.Context, projectID, userID uint) (bool, error)
	GetAllProjectUsers(ctx context.Context, projectID uint) ([]entities.User, error) // Including group users
	UpdateUserRole(ctx context.Context, projectID, userID uint, role string) error
	GetUserRole(ctx context.Context, projectID, userID uint) (string, error)
	BulkAddUsersToProject(ctx context.Context, req BulkAddUsersToProjectRequest) (*BulkOperationResult, error)
	BulkRemoveUsersFromProject(ctx context.Context, req BulkRemoveUsersFromProjectRequest) (*BulkOperationResult, error)

	// Group Management
	AddGroupToProject(ctx context.Context, projectID, groupID uint) error
	RemoveGroupFromProject(ctx context.Context, projectID, groupID uint) error
	GetProjectGroups(ctx context.Context, projectID uint) ([]entities.Group, error)
	GetGroupProjects(ctx context.Context, groupID uint) ([]entities.Project, error)
	IsGroupInProject(ctx context.Context, projectID, groupID uint) (bool, error)
	BulkAddGroupsToProject(ctx context.Context, req BulkAddGroupsToProjectRequest) (*BulkOperationResult, error)
	BulkRemoveGroupsFromProject(ctx context.Context, req BulkRemoveGroupsFromProjectRequest) (*BulkOperationResult, error)

	// Server Management
	AddServerToProject(ctx context.Context, projectID, serverID uint) error
	RemoveServerFromProject(ctx context.Context, projectID, serverID uint) error
	GetProjectServers(ctx context.Context, projectID uint) ([]entities.Server, error)
	GetServerProjects(ctx context.Context, serverID uint) ([]entities.Project, error)
	IsServerInProject(ctx context.Context, projectID, serverID uint) (bool, error)
	BulkAddServersToProject(ctx context.Context, req BulkAddServersToProjectRequest) (*BulkOperationResult, error)
	BulkRemoveServersFromProject(ctx context.Context, req BulkRemoveServersFromProjectRequest) (*BulkOperationResult, error)

	// Project Filtering and Search
	GetProjectsByOwner(ctx context.Context, ownerID uint) ([]entities.Project, error)
	GetProjectsByStatus(ctx context.Context, status entities.ProjectStatus) ([]entities.Project, error)
	GetProjectsByPriority(ctx context.Context, priority entities.ProjectPriority) ([]entities.Project, error)
	GetProjectsByDepartment(ctx context.Context, department string) ([]entities.Project, error)
	GetProjectsByEnvironment(ctx context.Context, environment string) ([]entities.Project, error)
	GetProjectsByDateRange(ctx context.Context, req ProjectDateRangeRequest) ([]entities.Project, error)
	SearchProjects(ctx context.Context, req SearchProjectsRequest) (*SearchProjectsResponse, error)
	GetActiveProjects(ctx context.Context) ([]entities.Project, error)
	GetOverdueProjects(ctx context.Context) ([]entities.Project, error)
	GetOverBudgetProjects(ctx context.Context) ([]entities.Project, error)

	// Budget Management
	UpdateProjectBudget(ctx context.Context, projectID uint, budget float64) error
	GetProjectBudgetInfo(ctx context.Context, projectID uint) (*repositories.ProjectBudgetInfo, error)
	RecordProjectExpense(ctx context.Context, req RecordProjectExpenseRequest) (*repositories.ProjectExpense, error)
	GetProjectExpenses(ctx context.Context, req GetProjectExpensesRequest) (*GetProjectExpensesResponse, error)
	ApproveExpense(ctx context.Context, expenseID uint, approvedBy uint) error
	RejectExpense(ctx context.Context, expenseID uint, rejectedBy uint, reason string) error
	GetBudgetSummary(ctx context.Context, projectID uint) (*repositories.BudgetSummary, error)
	GetBudgetAlerts(ctx context.Context, projectID uint) ([]BudgetAlert, error)

	// Timeline and Milestone Management
	AddProjectMilestone(ctx context.Context, req AddProjectMilestoneRequest) (*repositories.ProjectMilestone, error)
	UpdateProjectMilestone(ctx context.Context, milestoneID uint, req UpdateProjectMilestoneRequest) (*repositories.ProjectMilestone, error)
	DeleteProjectMilestone(ctx context.Context, milestoneID uint) error
	GetProjectMilestones(ctx context.Context, projectID uint) ([]repositories.ProjectMilestone, error)
	CompleteMilestone(ctx context.Context, milestoneID uint, completedBy uint, notes string) error
	GetProjectProgress(ctx context.Context, projectID uint) (*repositories.ProjectProgress, error)
	UpdateProjectProgress(ctx context.Context, projectID uint, percentage float64) error

	// Project Activity and Analytics
	GetProjectActivity(ctx context.Context, req ProjectActivityRequest) (*repositories.ProjectActivity, error)
	GetProjectMembersActivity(ctx context.Context, req ProjectMembersActivityRequest) ([]repositories.UserActivitySummary, error)
	GetProjectServerActivity(ctx context.Context, req ProjectServerActivityRequest) ([]repositories.ServerActivitySummary, error)
	GetRecentProjectChanges(ctx context.Context, projectID uint, limit int) ([]repositories.ProjectChange, error)
	GetProjectDashboard(ctx context.Context, req ProjectDashboardRequest) (*ProjectDashboardData, error)

	// Metadata and Settings Management
	UpdateProjectMetadata(ctx context.Context, projectID uint, metadata entities.ProjectMetadata) error
	UpdateProjectSettings(ctx context.Context, projectID uint, settings entities.ProjectSettings) error
	GetProjectMetadata(ctx context.Context, projectID uint) (*entities.ProjectMetadata, error)
	GetProjectSettings(ctx context.Context, projectID uint) (*entities.ProjectSettings, error)

	// Project Statistics
	GetProjectStats(ctx context.Context, projectID uint) (*repositories.ProjectStats, error)
	GetProjectSummary(ctx context.Context) (*repositories.ProjectSummary, error)
	GetProjectKPIs(ctx context.Context, projectID uint) (*repositories.ProjectKPIs, error)
	GetResourceUtilization(ctx context.Context, projectID uint) (*repositories.ResourceUtilization, error)

	// Access Control
	GetUserAccessibleProjects(ctx context.Context, userID uint) ([]entities.Project, error)
	CanUserManageProject(ctx context.Context, userID, projectID uint) (bool, error)
	GetProjectAdmins(ctx context.Context, projectID uint) ([]entities.User, error)
	GetProjectOwners(ctx context.Context, projectID uint) ([]entities.User, error)
	TransferProjectOwnership(ctx context.Context, projectID, newOwnerID uint, transferredBy uint) error

	// Bulk Operations
	BulkCreateProjects(ctx context.Context, req BulkCreateProjectsRequest) (*BulkCreateProjectsResult, error)
	BulkUpdateProjects(ctx context.Context, req BulkUpdateProjectsRequest) (*BulkUpdateProjectsResult, error)
	BulkDeleteProjects(ctx context.Context, req BulkDeleteProjectsRequest) (*BulkDeleteProjectsResult, error)
	BulkUpdateProjectStatus(ctx context.Context, req BulkUpdateProjectStatusRequest) (*BulkOperationResult, error)
	BulkUpdateProjectOwner(ctx context.Context, req BulkUpdateProjectOwnerRequest) (*BulkOperationResult, error)

	// Project Templates and Cloning
	CreateProjectTemplate(ctx context.Context, req CreateProjectTemplateRequest) (*repositories.ProjectTemplate, error)
	GetProjectTemplate(ctx context.Context, templateID uint) (*repositories.ProjectTemplate, error)
	ListProjectTemplates(ctx context.Context, req ListProjectTemplatesRequest) (*ListProjectTemplatesResponse, error)
	CreateProjectFromTemplate(ctx context.Context, req CreateProjectFromTemplateRequest) (*entities.Project, error)
	UpdateProjectTemplate(ctx context.Context, templateID uint, req UpdateProjectTemplateRequest) (*repositories.ProjectTemplate, error)
	DeleteProjectTemplate(ctx context.Context, templateID uint) error
	CloneProject(ctx context.Context, req CloneProjectRequest) (*CloneProjectResult, error)

	// Reporting and Analytics
	GenerateProjectReport(ctx context.Context, req GenerateProjectReportRequest) (*repositories.ProjectReport, error)
	GeneratePortfolioReport(ctx context.Context, req GeneratePortfolioReportRequest) (*repositories.PortfolioReport, error)
	GetProjectComparison(ctx context.Context, req ProjectComparisonRequest) (*ProjectComparisonResponse, error)
	GetProjectForecast(ctx context.Context, req ProjectForecastRequest) (*ProjectForecastResponse, error)

	// Risk Management
	AddProjectRisk(ctx context.Context, req AddProjectRiskRequest) (*repositories.ProjectRisk, error)
	UpdateProjectRisk(ctx context.Context, riskID string, req UpdateProjectRiskRequest) (*repositories.ProjectRisk, error)
	GetProjectRisks(ctx context.Context, projectID uint) ([]repositories.ProjectRisk, error)
	MitigateProjectRisk(ctx context.Context, riskID string, mitigation string, mitigatedBy uint) error
	GetRiskAssessment(ctx context.Context, projectID uint) (*ProjectRiskAssessment, error)

	// Cleanup Operations
	CleanupCompletedProjects(ctx context.Context, req CleanupCompletedProjectsRequest) (*CleanupResult, error)
	ArchiveOldProjects(ctx context.Context, req ArchiveOldProjectsRequest) (*CleanupResult, error)
	RemoveInactiveMembers(ctx context.Context, req RemoveInactiveMembersRequest) (*CleanupResult, error)
	ConsolidateProjects(ctx context.Context, req ConsolidateProjectsRequest) (*ConsolidationResult, error)

	// Import/Export
	ExportProject(ctx context.Context, req ExportProjectRequest) (*ExportProjectResult, error)
	ImportProjects(ctx context.Context, req ImportProjectsRequest) (*ImportProjectsResult, error)
	ExportProjectPortfolio(ctx context.Context, req ExportProjectPortfolioRequest) (*ExportResult, error)

	// Workflow Management
	CreateProjectWorkflow(ctx context.Context, req CreateProjectWorkflowRequest) (*ProjectWorkflow, error)
	GetProjectWorkflow(ctx context.Context, workflowID uint) (*ProjectWorkflow, error)
	UpdateProjectWorkflow(ctx context.Context, workflowID uint, req UpdateProjectWorkflowRequest) (*ProjectWorkflow, error)
	ExecuteWorkflowStep(ctx context.Context, req ExecuteWorkflowStepRequest) (*WorkflowStepResult, error)
	GetProjectWorkflowStatus(ctx context.Context, projectID uint) (*ProjectWorkflowStatus, error)

	// Notification Management
	CreateProjectNotification(ctx context.Context, req CreateProjectNotificationRequest) error
	GetProjectNotifications(ctx context.Context, projectID uint) ([]ProjectNotification, error)
	MarkNotificationRead(ctx context.Context, notificationID string, userID uint) error
	GetUserProjectNotifications(ctx context.Context, userID uint) ([]ProjectNotification, error)
}

// Request/Response DTOs

type CreateProjectRequest struct {
	Name        string                   `json:"name" validate:"required,min=1,max=100"`
	Code        string                   `json:"code" validate:"required,min=2,max=20,alphanum"`
	Description string                   `json:"description,omitempty"`
	Status      entities.ProjectStatus   `json:"status,omitempty"`
	Priority    entities.ProjectPriority `json:"priority,omitempty"`
	StartDate   *time.Time               `json:"start_date,omitempty"`
	EndDate     *time.Time               `json:"end_date,omitempty"`
	Budget      float64                  `json:"budget,omitempty" validate:"omitempty,min=0"`
	OwnerID     uint                     `json:"owner_id" validate:"required"`
	Metadata    entities.ProjectMetadata `json:"metadata,omitempty"`
	Settings    entities.ProjectSettings `json:"settings,omitempty"`
	UserIDs     []uint                   `json:"user_ids,omitempty"`
	GroupIDs    []uint                   `json:"group_ids,omitempty"`
	ServerIDs   []uint                   `json:"server_ids,omitempty"`
	Tags        []string                 `json:"tags,omitempty"`
}

type UpdateProjectRequest struct {
	Name        *string                   `json:"name,omitempty" validate:"omitempty,min=1,max=100"`
	Description *string                   `json:"description,omitempty"`
	Status      *entities.ProjectStatus   `json:"status,omitempty"`
	Priority    *entities.ProjectPriority `json:"priority,omitempty"`
	StartDate   *time.Time                `json:"start_date,omitempty"`
	EndDate     *time.Time                `json:"end_date,omitempty"`
	Budget      *float64                  `json:"budget,omitempty" validate:"omitempty,min=0"`
	OwnerID     *uint                     `json:"owner_id,omitempty"`
	Metadata    *entities.ProjectMetadata `json:"metadata,omitempty"`
	Settings    *entities.ProjectSettings `json:"settings,omitempty"`
	Tags        []string                  `json:"tags,omitempty"`
}

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
	UserID       *uint    `json:"user_id,omitempty"`   // Filter projects containing this user
	GroupID      *uint    `json:"group_id,omitempty"`  // Filter projects containing this group
	ServerID     *uint    `json:"server_id,omitempty"` // Filter projects containing this server
	MinBudget    *float64 `json:"min_budget,omitempty"`
	MaxBudget    *float64 `json:"max_budget,omitempty"`
	Page         int      `json:"page,omitempty"`
	PageSize     int      `json:"page_size,omitempty"`
	SortBy       string   `json:"sort_by,omitempty"`
	SortOrder    string   `json:"sort_order,omitempty"`
	IncludeStats bool     `json:"include_stats,omitempty"`
}

type ListProjectsResponse struct {
	Projects   []entities.Project             `json:"projects"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *repositories.ProjectSummary   `json:"summary"`
	Filters    *AppliedProjectFilters         `json:"filters"`
}

type AppliedProjectFilters struct {
	Status       string   `json:"status,omitempty"`
	Priority     string   `json:"priority,omitempty"`
	OwnerID      *uint    `json:"owner_id,omitempty"`
	Department   string   `json:"department,omitempty"`
	IsOverdue    *bool    `json:"is_overdue,omitempty"`
	IsOverBudget *bool    `json:"is_over_budget,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	Search       string   `json:"search,omitempty"`
	FilterCount  int      `json:"filter_count"`
}

type ProjectDateRangeRequest struct {
	StartAfter  *time.Time `json:"start_after,omitempty"`
	StartBefore *time.Time `json:"start_before,omitempty"`
	EndAfter    *time.Time `json:"end_after,omitempty"`
	EndBefore   *time.Time `json:"end_before,omitempty"`
}

type SearchProjectsRequest struct {
	Query      string   `json:"query" validate:"required,min=1"`
	SearchIn   []string `json:"search_in,omitempty"` // name, description, code, etc.
	Status     string   `json:"status,omitempty"`
	Priority   string   `json:"priority,omitempty"`
	Department string   `json:"department,omitempty"`
	OwnerID    *uint    `json:"owner_id,omitempty"`
	MinBudget  *float64 `json:"min_budget,omitempty"`
	MaxBudget  *float64 `json:"max_budget,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	Page       int      `json:"page,omitempty"`
	PageSize   int      `json:"page_size,omitempty"`
	SortBy     string   `json:"sort_by,omitempty"`
	SortOrder  string   `json:"sort_order,omitempty"`
	Highlights bool     `json:"highlights,omitempty"`
}

type SearchProjectsResponse struct {
	Projects   []entities.Project             `json:"projects"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *SearchProjectsSummary         `json:"summary"`
	Query      string                         `json:"query"`
	Highlights map[uint][]string              `json:"highlights,omitempty"` // ProjectID -> highlighted fields
}

type SearchProjectsSummary struct {
	TotalResults  int64            `json:"total_results"`
	ByStatus      map[string]int64 `json:"by_status"`
	ByPriority    map[string]int64 `json:"by_priority"`
	ByDepartment  map[string]int64 `json:"by_department"`
	MatchedFields []string         `json:"matched_fields"`
	AvgRelevance  float64          `json:"avg_relevance"`
}

type BulkAddUsersToProjectRequest struct {
	ProjectID uint   `json:"project_id" validate:"required"`
	UserIDs   []uint `json:"user_ids" validate:"required,min=1,max=100"`
	Role      string `json:"role,omitempty"`
}

type BulkRemoveUsersFromProjectRequest struct {
	ProjectID uint   `json:"project_id" validate:"required"`
	UserIDs   []uint `json:"user_ids" validate:"required,min=1,max=100"`
}

type BulkAddGroupsToProjectRequest struct {
	ProjectID uint   `json:"project_id" validate:"required"`
	GroupIDs  []uint `json:"group_ids" validate:"required,min=1,max=50"`
}

type BulkRemoveGroupsFromProjectRequest struct {
	ProjectID uint   `json:"project_id" validate:"required"`
	GroupIDs  []uint `json:"group_ids" validate:"required,min=1,max=50"`
}

type BulkAddServersToProjectRequest struct {
	ProjectID uint   `json:"project_id" validate:"required"`
	ServerIDs []uint `json:"server_ids" validate:"required,min=1,max=100"`
}

type BulkRemoveServersFromProjectRequest struct {
	ProjectID uint   `json:"project_id" validate:"required"`
	ServerIDs []uint `json:"server_ids" validate:"required,min=1,max=100"`
}

type RecordProjectExpenseRequest struct {
	ProjectID   uint      `json:"project_id" validate:"required"`
	Category    string    `json:"category" validate:"required"`
	Description string    `json:"description" validate:"required"`
	Amount      float64   `json:"amount" validate:"required,min=0"`
	Currency    string    `json:"currency,omitempty"`
	Date        time.Time `json:"date" validate:"required"`
	ReceiptURL  string    `json:"receipt_url,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	SubmittedBy uint      `json:"submitted_by" validate:"required"`
}

type GetProjectExpensesRequest struct {
	ProjectID   uint       `json:"project_id" validate:"required"`
	Category    string     `json:"category,omitempty"`
	Status      string     `json:"status,omitempty"`
	SubmittedBy *uint      `json:"submitted_by,omitempty"`
	ApprovedBy  *uint      `json:"approved_by,omitempty"`
	DateFrom    *time.Time `json:"date_from,omitempty"`
	DateTo      *time.Time `json:"date_to,omitempty"`
	MinAmount   *float64   `json:"min_amount,omitempty"`
	MaxAmount   *float64   `json:"max_amount,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
	Page        int        `json:"page,omitempty"`
	PageSize    int        `json:"page_size,omitempty"`
	SortBy      string     `json:"sort_by,omitempty"`
	SortOrder   string     `json:"sort_order,omitempty"`
}

type GetProjectExpensesResponse struct {
	Expenses   []repositories.ProjectExpense  `json:"expenses"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *ProjectExpensesSummary        `json:"summary"`
}

type ProjectExpensesSummary struct {
	TotalExpenses    int64                         `json:"total_expenses"`
	TotalAmount      float64                       `json:"total_amount"`
	PendingExpenses  int64                         `json:"pending_expenses"`
	ApprovedExpenses int64                         `json:"approved_expenses"`
	RejectedExpenses int64                         `json:"rejected_expenses"`
	ByCategory       map[string]float64            `json:"by_category"`
	ByStatus         map[string]int64              `json:"by_status"`
	ByMonth          []repositories.MonthlyExpense `json:"by_month"`
}

type BudgetAlert struct {
	ID           string  `json:"id"`
	ProjectID    uint    `json:"project_id"`
	Type         string  `json:"type"` // budget_exceeded, budget_warning, burn_rate_high
	Severity     string  `json:"severity"`
	Message      string  `json:"message"`
	Threshold    float64 `json:"threshold"`
	CurrentValue float64 `json:"current_value"`
	TriggeredAt  string  `json:"triggered_at"`
	IsActive     bool    `json:"is_active"`
}

type AddProjectMilestoneRequest struct {
	ProjectID    uint       `json:"project_id" validate:"required"`
	Name         string     `json:"name" validate:"required"`
	Description  string     `json:"description,omitempty"`
	DueDate      *time.Time `json:"due_date,omitempty"`
	Status       string     `json:"status,omitempty"`
	Priority     string     `json:"priority,omitempty"`
	AssignedTo   *uint      `json:"assigned_to,omitempty"`
	Dependencies []string   `json:"dependencies,omitempty"`
	Tags         []string   `json:"tags,omitempty"`
	CreatedBy    uint       `json:"created_by" validate:"required"`
}

type UpdateProjectMilestoneRequest struct {
	Name         *string    `json:"name,omitempty"`
	Description  *string    `json:"description,omitempty"`
	DueDate      *time.Time `json:"due_date,omitempty"`
	Status       *string    `json:"status,omitempty"`
	Priority     *string    `json:"priority,omitempty"`
	AssignedTo   *uint      `json:"assigned_to,omitempty"`
	Dependencies []string   `json:"dependencies,omitempty"`
	Tags         []string   `json:"tags,omitempty"`
	Progress     *float64   `json:"progress,omitempty"`
}

type ProjectActivityRequest struct {
	ProjectID uint                   `json:"project_id" validate:"required"`
	TimeRange repositories.TimeRange `json:"time_range"`
	Metrics   []string               `json:"metrics,omitempty"`
}

type ProjectMembersActivityRequest struct {
	ProjectID uint                   `json:"project_id" validate:"required"`
	TimeRange repositories.TimeRange `json:"time_range"`
	Limit     int                    `json:"limit,omitempty"`
	SortBy    string                 `json:"sort_by,omitempty"`
}

type ProjectServerActivityRequest struct {
	ProjectID uint                   `json:"project_id" validate:"required"`
	TimeRange repositories.TimeRange `json:"time_range"`
	Limit     int                    `json:"limit,omitempty"`
	SortBy    string                 `json:"sort_by,omitempty"`
}

type ProjectDashboardRequest struct {
	ProjectID   uint                   `json:"project_id" validate:"required"`
	Widgets     []string               `json:"widgets,omitempty"`
	TimeRange   repositories.TimeRange `json:"time_range,omitempty"`
	RefreshRate int                    `json:"refresh_rate,omitempty"` // seconds
}

type ProjectDashboardData struct {
	Project        *entities.Project                `json:"project"`
	Summary        *repositories.ProjectStats       `json:"summary"`
	Progress       *repositories.ProjectProgress    `json:"progress"`
	Budget         *repositories.BudgetSummary      `json:"budget"`
	RecentActivity []repositories.ProjectChange     `json:"recent_activity"`
	Milestones     []repositories.ProjectMilestone  `json:"milestones"`
	Members        []repositories.ProjectMemberInfo `json:"members"`
	Servers        []repositories.ProjectServerInfo `json:"servers"`
	Risks          []repositories.ProjectRisk       `json:"risks"`
	Alerts         []ProjectAlert                   `json:"alerts"`
	Charts         []ChartData                      `json:"charts"`
	UpdatedAt      string                           `json:"updated_at"`
}

type ProjectAlert struct {
	ID         string                 `json:"id"`
	ProjectID  uint                   `json:"project_id"`
	Type       string                 `json:"type"`
	Severity   string                 `json:"severity"`
	Title      string                 `json:"title"`
	Message    string                 `json:"message"`
	CreatedAt  string                 `json:"created_at"`
	IsRead     bool                   `json:"is_read"`
	ActionURL  string                 `json:"action_url,omitempty"`
	ActionText string                 `json:"action_text,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type ChartData struct {
	Type   string                 `json:"type"`
	Title  string                 `json:"title"`
	Data   interface{}            `json:"data"`
	Config map[string]interface{} `json:"config,omitempty"`
}

type BulkCreateProjectsRequest struct {
	Projects []CreateProjectRequest `json:"projects" validate:"required,min=1,max=20"`
}

type BulkCreateProjectsResult struct {
	TotalRequested  int                  `json:"total_requested"`
	Successful      int                  `json:"successful"`
	Failed          int                  `json:"failed"`
	CreatedProjects []entities.Project   `json:"created_projects"`
	Errors          []BulkOperationError `json:"errors,omitempty"`
}

type BulkUpdateProjectsRequest struct {
	Updates []ProjectUpdateItem `json:"updates" validate:"required,min=1,max=50"`
}

type ProjectUpdateItem struct {
	ID   uint                 `json:"id" validate:"required"`
	Data UpdateProjectRequest `json:"data"`
}

type BulkUpdateProjectsResult struct {
	TotalRequested  int                  `json:"total_requested"`
	Successful      int                  `json:"successful"`
	Failed          int                  `json:"failed"`
	UpdatedProjects []entities.Project   `json:"updated_projects"`
	Errors          []BulkOperationError `json:"errors,omitempty"`
}

type BulkDeleteProjectsRequest struct {
	ProjectIDs []uint `json:"project_ids" validate:"required,min=1,max=50"`
	Force      bool   `json:"force,omitempty"`   // Delete even if has dependencies
	Archive    bool   `json:"archive,omitempty"` // Archive instead of delete
}

type BulkDeleteProjectsResult struct {
	TotalRequested   int                  `json:"total_requested"`
	Successful       int                  `json:"successful"`
	Failed           int                  `json:"failed"`
	DeletedProjects  []uint               `json:"deleted_projects"`
	ArchivedProjects []uint               `json:"archived_projects"`
	Errors           []BulkOperationError `json:"errors,omitempty"`
}

type BulkUpdateProjectStatusRequest struct {
	ProjectIDs []uint                 `json:"project_ids" validate:"required,min=1,max=50"`
	Status     entities.ProjectStatus `json:"status" validate:"required"`
	Reason     string                 `json:"reason,omitempty"`
}

type BulkUpdateProjectOwnerRequest struct {
	ProjectIDs []uint `json:"project_ids" validate:"required,min=1,max=50"`
	NewOwnerID uint   `json:"new_owner_id" validate:"required"`
	Reason     string `json:"reason,omitempty"`
}

type CreateProjectTemplateRequest struct {
	ProjectID   uint   `json:"project_id" validate:"required"`
	Name        string `json:"name" validate:"required"`
	Description string `json:"description,omitempty"`
	Category    string `json:"category,omitempty"`
	IsPublic    bool   `json:"is_public,omitempty"`
}

type ListProjectTemplatesRequest struct {
	Category  string `json:"category,omitempty"`
	IsPublic  *bool  `json:"is_public,omitempty"`
	CreatedBy *uint  `json:"created_by,omitempty"`
	Search    string `json:"search,omitempty"`
	Page      int    `json:"page,omitempty"`
	PageSize  int    `json:"page_size,omitempty"`
	SortBy    string `json:"sort_by,omitempty"`
	SortOrder string `json:"sort_order,omitempty"`
}

type ListProjectTemplatesResponse struct {
	Templates  []repositories.ProjectTemplate `json:"templates"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *ProjectTemplatesSummary       `json:"summary"`
}

type ProjectTemplatesSummary struct {
	Total      int64            `json:"total"`
	Public     int64            `json:"public"`
	Private    int64            `json:"private"`
	ByCategory map[string]int64 `json:"by_category"`
	ByUsage    []TemplateUsage  `json:"by_usage"`
}

type TemplateUsage struct {
	TemplateID   uint   `json:"template_id"`
	TemplateName string `json:"template_name"`
	UsageCount   int64  `json:"usage_count"`
}

type CreateProjectFromTemplateRequest struct {
	TemplateID uint                   `json:"template_id" validate:"required"`
	Name       string                 `json:"name" validate:"required"`
	Code       string                 `json:"code" validate:"required"`
	OwnerID    uint                   `json:"owner_id" validate:"required"`
	StartDate  *time.Time             `json:"start_date,omitempty"`
	Budget     *float64               `json:"budget,omitempty"`
	Overrides  map[string]interface{} `json:"overrides,omitempty"`
}

type UpdateProjectTemplateRequest struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	Category    *string `json:"category,omitempty"`
	IsPublic    *bool   `json:"is_public,omitempty"`
}

type CloneProjectRequest struct {
	ProjectID         uint       `json:"project_id" validate:"required"`
	NewName           string     `json:"new_name" validate:"required"`
	NewCode           string     `json:"new_code" validate:"required"`
	NewOwnerID        uint       `json:"new_owner_id" validate:"required"`
	IncludeMembers    bool       `json:"include_members,omitempty"`
	IncludeServers    bool       `json:"include_servers,omitempty"`
	IncludeGroups     bool       `json:"include_groups,omitempty"`
	IncludeBudget     bool       `json:"include_budget,omitempty"`
	IncludeMilestones bool       `json:"include_milestones,omitempty"`
	IncludeSettings   bool       `json:"include_settings,omitempty"`
	StartDate         *time.Time `json:"start_date,omitempty"`
	EndDate           *time.Time `json:"end_date,omitempty"`
}

type CloneProjectResult struct {
	OriginalProject  *entities.Project `json:"original_project"`
	ClonedProject    *entities.Project `json:"cloned_project"`
	CopiedMembers    int               `json:"copied_members"`
	CopiedServers    int               `json:"copied_servers"`
	CopiedGroups     int               `json:"copied_groups"`
	CopiedMilestones int               `json:"copied_milestones"`
	Warnings         []string          `json:"warnings,omitempty"`
}

type GenerateProjectReportRequest struct {
	ProjectID       uint                   `json:"project_id" validate:"required"`
	ReportType      string                 `json:"report_type" validate:"required,oneof=summary detailed budget activity progress"`
	TimeRange       repositories.TimeRange `json:"time_range,omitempty"`
	Format          string                 `json:"format" validate:"required,oneof=json pdf excel"`
	IncludeBudget   bool                   `json:"include_budget,omitempty"`
	IncludeMembers  bool                   `json:"include_members,omitempty"`
	IncludeServers  bool                   `json:"include_servers,omitempty"`
	IncludeRisks    bool                   `json:"include_risks,omitempty"`
	IncludeTimeline bool                   `json:"include_timeline,omitempty"`
}

type GeneratePortfolioReportRequest struct {
	ProjectIDs      []uint                 `json:"project_ids,omitempty"` // If empty, include all
	OwnerID         *uint                  `json:"owner_id,omitempty"`
	Department      string                 `json:"department,omitempty"`
	Status          string                 `json:"status,omitempty"`
	Priority        string                 `json:"priority,omitempty"`
	TimeRange       repositories.TimeRange `json:"time_range,omitempty"`
	Format          string                 `json:"format" validate:"required,oneof=json pdf excel"`
	GroupBy         string                 `json:"group_by,omitempty" validate:"omitempty,oneof=status priority department owner"`
	IncludeBudget   bool                   `json:"include_budget,omitempty"`
	IncludeProgress bool                   `json:"include_progress,omitempty"`
	IncludeRisks    bool                   `json:"include_risks,omitempty"`
}

type ProjectComparisonRequest struct {
	ProjectIDs []uint                 `json:"project_ids" validate:"required,min=2,max=10"`
	Metrics    []string               `json:"metrics,omitempty"`
	TimeRange  repositories.TimeRange `json:"time_range,omitempty"`
}

type ProjectComparisonResponse struct {
	Projects   []entities.Project        `json:"projects"`
	Comparison []ProjectComparisonItem   `json:"comparison"`
	Summary    *ProjectComparisonSummary `json:"summary"`
	Charts     []ChartData               `json:"charts,omitempty"`
}

type ProjectComparisonItem struct {
	Metric string               `json:"metric"`
	Values map[uint]interface{} `json:"values"` // ProjectID -> Value
	Unit   string               `json:"unit,omitempty"`
	Trend  map[uint]string      `json:"trend,omitempty"` // ProjectID -> up/down/stable
}

type ProjectComparisonSummary struct {
	TotalProjects      int                `json:"total_projects"`
	BestPerformers     map[string]uint    `json:"best_performers"`  // Metric -> ProjectID
	WorstPerformers    map[string]uint    `json:"worst_performers"` // Metric -> ProjectID
	Averages           map[string]float64 `json:"averages"`
	StandardDeviations map[string]float64 `json:"standard_deviations"`
}

type ProjectForecastRequest struct {
	ProjectID    uint   `json:"project_id" validate:"required"`
	ForecastType string `json:"forecast_type" validate:"required,oneof=budget timeline completion risk"`
	ForecastDays int    `json:"forecast_days" validate:"required,min=1,max=365"`
	Algorithm    string `json:"algorithm,omitempty" validate:"omitempty,oneof=linear exponential seasonal"`
}

type ProjectForecastResponse struct {
	ProjectID       uint            `json:"project_id"`
	ForecastType    string          `json:"forecast_type"`
	Algorithm       string          `json:"algorithm"`
	Forecast        []ForecastPoint `json:"forecast"`
	Confidence      float64         `json:"confidence"`
	Risks           []ForecastRisk  `json:"risks"`
	Recommendations []string        `json:"recommendations"`
	GeneratedAt     string          `json:"generated_at"`
}

type ForecastPoint struct {
	Date  string      `json:"date"`
	Value interface{} `json:"value"`
	Lower interface{} `json:"lower,omitempty"` // Confidence interval
	Upper interface{} `json:"upper,omitempty"` // Confidence interval
}

type ForecastRisk struct {
	Type        string  `json:"type"`
	Probability float64 `json:"probability"`
	Impact      string  `json:"impact"`
	Description string  `json:"description"`
	Mitigation  string  `json:"mitigation,omitempty"`
}

type AddProjectRiskRequest struct {
	ProjectID   uint   `json:"project_id" validate:"required"`
	Type        string `json:"type" validate:"required"`
	Title       string `json:"title" validate:"required"`
	Description string `json:"description" validate:"required"`
	Severity    string `json:"severity" validate:"required,oneof=low medium high critical"`
	Probability string `json:"probability" validate:"required,oneof=low medium high very_high"`
	Impact      string `json:"impact" validate:"required,oneof=low medium high critical"`
	Mitigation  string `json:"mitigation,omitempty"`
	Owner       string `json:"owner,omitempty"`
}

type UpdateProjectRiskRequest struct {
	Type        *string `json:"type,omitempty"`
	Title       *string `json:"title,omitempty"`
	Description *string `json:"description,omitempty"`
	Severity    *string `json:"severity,omitempty"`
	Probability *string `json:"probability,omitempty"`
	Impact      *string `json:"impact,omitempty"`
	Mitigation  *string `json:"mitigation,omitempty"`
	Owner       *string `json:"owner,omitempty"`
	Status      *string `json:"status,omitempty"`
}

type ProjectRiskAssessment struct {
	ProjectID       uint                       `json:"project_id"`
	OverallRisk     string                     `json:"overall_risk"` // low, medium, high, critical
	RiskScore       float64                    `json:"risk_score"`
	TotalRisks      int64                      `json:"total_risks"`
	ActiveRisks     int64                      `json:"active_risks"`
	MitigatedRisks  int64                      `json:"mitigated_risks"`
	RisksByCategory map[string]int64           `json:"risks_by_category"`
	RisksBySeverity map[string]int64           `json:"risks_by_severity"`
	TopRisks        []repositories.ProjectRisk `json:"top_risks"`
	RiskTrend       []RiskTrendPoint           `json:"risk_trend"`
	Recommendations []RiskRecommendation       `json:"recommendations"`
	AssessedAt      string                     `json:"assessed_at"`
}

type RiskTrendPoint struct {
	Date      string  `json:"date"`
	RiskScore float64 `json:"risk_score"`
	NewRisks  int64   `json:"new_risks"`
	Mitigated int64   `json:"mitigated"`
}

type RiskRecommendation struct {
	Priority    string `json:"priority"`
	Action      string `json:"action"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
}

type CleanupCompletedProjectsRequest struct {
	OlderThanDays   int    `json:"older_than_days" validate:"required,min=1"`
	ArchiveFirst    bool   `json:"archive_first,omitempty"`
	ArchiveLocation string `json:"archive_location,omitempty"`
	DryRun          bool   `json:"dry_run,omitempty"`
}

type ArchiveOldProjectsRequest struct {
	OlderThanDays   int      `json:"older_than_days" validate:"required,min=1"`
	Statuses        []string `json:"statuses,omitempty"` // Which statuses to archive
	ArchiveLocation string   `json:"archive_location" validate:"required"`
	Compress        bool     `json:"compress,omitempty"`
	DryRun          bool     `json:"dry_run,omitempty"`
}

type RemoveInactiveMembersRequest struct {
	ProjectID             uint `json:"project_id" validate:"required"`
	DaysSinceLastActivity int  `json:"days_since_last_activity" validate:"required,min=1"`
	OnlyInactiveUsers     bool `json:"only_inactive_users,omitempty"`
	DryRun                bool `json:"dry_run,omitempty"`
}

type ConsolidateProjectsRequest struct {
	SimilarityThreshold float64  `json:"similarity_threshold" validate:"required,min=0,max=1"`
	Department          string   `json:"department,omitempty"`
	OwnerID             *uint    `json:"owner_id,omitempty"`
	Statuses            []string `json:"statuses,omitempty"`
	DryRun              bool     `json:"dry_run,omitempty"`
	AutoMerge           bool     `json:"auto_merge,omitempty"`
}

type ConsolidationResult struct {
	CandidatePairs   []ConsolidationCandidate `json:"candidate_pairs"`
	AutoMerged       []MergeProjectResult     `json:"auto_merged,omitempty"`
	TotalCandidates  int                      `json:"total_candidates"`
	MergedProjects   int                      `json:"merged_projects"`
	PotentialSavings float64                  `json:"potential_savings"`
	WasDryRun        bool                     `json:"was_dry_run"`
}

type ConsolidationCandidate struct {
	Project1ID       uint    `json:"project1_id"`
	Project1Name     string  `json:"project1_name"`
	Project2ID       uint    `json:"project2_id"`
	Project2Name     string  `json:"project2_name"`
	Similarity       float64 `json:"similarity"`
	CommonMembers    int64   `json:"common_members"`
	CommonServers    int64   `json:"common_servers"`
	MergeStrategy    string  `json:"merge_strategy"`
	EstimatedSavings float64 `json:"estimated_savings"`
}

type MergeProjectResult struct {
	SourceProject *entities.Project `json:"source_project"`
	TargetProject *entities.Project `json:"target_project"`
	MergedMembers int               `json:"merged_members"`
	MergedServers int               `json:"merged_servers"`
	MergedBudget  float64           `json:"merged_budget"`
	Conflicts     []string          `json:"conflicts,omitempty"`
}

type ExportProjectRequest struct {
	ProjectID         uint   `json:"project_id" validate:"required"`
	Format            string `json:"format" validate:"required,oneof=json yaml excel"`
	IncludeMembers    bool   `json:"include_members,omitempty"`
	IncludeServers    bool   `json:"include_servers,omitempty"`
	IncludeGroups     bool   `json:"include_groups,omitempty"`
	IncludeBudget     bool   `json:"include_budget,omitempty"`
	IncludeMilestones bool   `json:"include_milestones,omitempty"`
	IncludeActivity   bool   `json:"include_activity,omitempty"`
	IncludeRisks      bool   `json:"include_risks,omitempty"`
}

type ExportProjectResult struct {
	Data        []byte `json:"data"`
	FileName    string `json:"file_name"`
	Format      string `json:"format"`
	Size        int64  `json:"size"`
	ExportedAt  string `json:"exported_at"`
	DownloadURL string `json:"download_url,omitempty"`
}

type ImportProjectsRequest struct {
	Data         []byte            `json:"data" validate:"required"`
	Format       string            `json:"format" validate:"required,oneof=json yaml excel csv"`
	ImportMode   string            `json:"import_mode" validate:"required,oneof=create update upsert"`
	FieldMapping map[string]string `json:"field_mapping,omitempty"`
	DryRun       bool              `json:"dry_run,omitempty"`
	Validation   bool              `json:"validation,omitempty"`
}

type ImportProjectsResult struct {
	TotalProjects    int                `json:"total_projects"`
	CreatedProjects  int                `json:"created_projects"`
	UpdatedProjects  int                `json:"updated_projects"`
	SkippedProjects  int                `json:"skipped_projects"`
	FailedProjects   int                `json:"failed_projects"`
	Errors           []ImportError      `json:"errors,omitempty"`
	Warnings         []ImportWarning    `json:"warnings,omitempty"`
	WasDryRun        bool               `json:"was_dry_run"`
	ImportedProjects []entities.Project `json:"imported_projects,omitempty"`
}

type ExportProjectPortfolioRequest struct {
	OwnerID      *uint  `json:"owner_id,omitempty"`
	Department   string `json:"department,omitempty"`
	Status       string `json:"status,omitempty"`
	Priority     string `json:"priority,omitempty"`
	ProjectIDs   []uint `json:"project_ids,omitempty"`
	Format       string `json:"format" validate:"required,oneof=json excel csv"`
	IncludeStats bool   `json:"include_stats,omitempty"`
	GroupBy      string `json:"group_by,omitempty"`
}

type ProjectWorkflow struct {
	ID          uint                  `json:"id"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	ProjectID   *uint                 `json:"project_id,omitempty"` // If nil, global workflow
	Steps       []ProjectWorkflowStep `json:"steps"`
	IsActive    bool                  `json:"is_active"`
	CreatedBy   uint                  `json:"created_by"`
	CreatedAt   string                `json:"created_at"`
	UpdatedAt   string                `json:"updated_at"`
}

type ProjectWorkflowStep struct {
	ID           uint                   `json:"id"`
	WorkflowID   uint                   `json:"workflow_id"`
	StepNumber   int                    `json:"step_number"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Type         string                 `json:"type"` // approval, notification, action, milestone
	AssignedTo   []uint                 `json:"assigned_to,omitempty"`
	RequiredRole string                 `json:"required_role,omitempty"`
	AutoExecute  bool                   `json:"auto_execute"`
	TimeoutHours int                    `json:"timeout_hours"`
	Conditions   map[string]interface{} `json:"conditions,omitempty"`
	Actions      map[string]interface{} `json:"actions,omitempty"`
}

type CreateProjectWorkflowRequest struct {
	Name        string                `json:"name" validate:"required"`
	Description string                `json:"description,omitempty"`
	ProjectID   *uint                 `json:"project_id,omitempty"`
	Steps       []ProjectWorkflowStep `json:"steps" validate:"required,min=1"`
	IsActive    bool                  `json:"is_active,omitempty"`
}

type UpdateProjectWorkflowRequest struct {
	Name        *string               `json:"name,omitempty"`
	Description *string               `json:"description,omitempty"`
	Steps       []ProjectWorkflowStep `json:"steps,omitempty"`
	IsActive    *bool                 `json:"is_active,omitempty"`
}

type ExecuteWorkflowStepRequest struct {
	WorkflowID uint                   `json:"workflow_id" validate:"required"`
	StepID     uint                   `json:"step_id" validate:"required"`
	ProjectID  uint                   `json:"project_id" validate:"required"`
	ExecutedBy uint                   `json:"executed_by" validate:"required"`
	Action     string                 `json:"action" validate:"required,oneof=approve reject complete skip"`
	Comments   string                 `json:"comments,omitempty"`
	Data       map[string]interface{} `json:"data,omitempty"`
}

type WorkflowStepResult struct {
	StepID      uint                   `json:"step_id"`
	Status      string                 `json:"status"`
	Result      string                 `json:"result"`
	NextStepID  *uint                  `json:"next_step_id,omitempty"`
	CompletedAt string                 `json:"completed_at"`
	Data        map[string]interface{} `json:"data,omitempty"`
	Errors      []string               `json:"errors,omitempty"`
}

type ProjectWorkflowStatus struct {
	ProjectID      uint                 `json:"project_id"`
	WorkflowID     *uint                `json:"workflow_id,omitempty"`
	CurrentStepID  *uint                `json:"current_step_id,omitempty"`
	Status         string               `json:"status"` // not_started, in_progress, completed, failed
	Progress       float64              `json:"progress"`
	StartedAt      *string              `json:"started_at,omitempty"`
	CompletedAt    *string              `json:"completed_at,omitempty"`
	CompletedSteps []WorkflowStepStatus `json:"completed_steps"`
	PendingSteps   []WorkflowStepStatus `json:"pending_steps"`
	BlockedSteps   []WorkflowStepStatus `json:"blocked_steps"`
}

type WorkflowStepStatus struct {
	StepID      uint    `json:"step_id"`
	StepName    string  `json:"step_name"`
	Status      string  `json:"status"`
	AssignedTo  []uint  `json:"assigned_to,omitempty"`
	StartedAt   *string `json:"started_at,omitempty"`
	CompletedAt *string `json:"completed_at,omitempty"`
	Comments    string  `json:"comments,omitempty"`
}

type CreateProjectNotificationRequest struct {
	ProjectID   uint                   `json:"project_id" validate:"required"`
	Type        string                 `json:"type" validate:"required"`
	Title       string                 `json:"title" validate:"required"`
	Message     string                 `json:"message" validate:"required"`
	Recipients  []uint                 `json:"recipients,omitempty"` // User IDs, if empty send to all project members
	Channels    []string               `json:"channels,omitempty"`   // email, slack, teams
	Priority    string                 `json:"priority,omitempty"`
	ScheduledAt *time.Time             `json:"scheduled_at,omitempty"`
	Data        map[string]interface{} `json:"data,omitempty"`
}

type ProjectNotification struct {
	ID          string                 `json:"id"`
	ProjectID   uint                   `json:"project_id"`
	ProjectName string                 `json:"project_name"`
	Type        string                 `json:"type"`
	Title       string                 `json:"title"`
	Message     string                 `json:"message"`
	Priority    string                 `json:"priority"`
	CreatedAt   string                 `json:"created_at"`
	ReadAt      *string                `json:"read_at,omitempty"`
	IsRead      bool                   `json:"is_read"`
	ActionURL   string                 `json:"action_url,omitempty"`
	ActionText  string                 `json:"action_text,omitempty"`
	Data        map[string]interface{} `json:"data,omitempty"`
}

// Shared types from other services
type BulkOperationResult struct {
	TotalRequested int                  `json:"total_requested"`
	Successful     int                  `json:"successful"`
	Failed         int                  `json:"failed"`
	Errors         []BulkOperationError `json:"errors,omitempty"`
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
	WasDryRun      bool     `json:"was_dry_run"`
}

type ExportResult struct {
	FileName    string `json:"file_name"`
	Format      string `json:"format"`
	Size        int64  `json:"size"`
	RecordCount int64  `json:"record_count"`
	ExportedAt  string `json:"exported_at"`
	DownloadURL string `json:"download_url,omitempty"`
}

type ImportError struct {
	Row     int               `json:"row"`
	Column  string            `json:"column,omitempty"`
	Field   string            `json:"field,omitempty"`
	Value   interface{}       `json:"value,omitempty"`
	Message string            `json:"message"`
	Code    string            `json:"code,omitempty"`
	Data    map[string]string `json:"data,omitempty"`
}

type ImportWarning struct {
	Row     int               `json:"row"`
	Message string            `json:"message"`
	Field   string            `json:"field,omitempty"`
	Data    map[string]string `json:"data,omitempty"`
}
