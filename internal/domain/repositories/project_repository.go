package repositories

import (
	"context"
	"ssh-access-management/internal/domain/entities"
	"time"
)

// ProjectRepository defines project repository interface
type ProjectRepository interface {
	// Project CRUD operations
	Create(ctx context.Context, project *entities.Project) error
	GetByID(ctx context.Context, id uint) (*entities.Project, error)
	GetByName(ctx context.Context, name string) (*entities.Project, error)
	GetByCode(ctx context.Context, code string) (*entities.Project, error)
	Update(ctx context.Context, project *entities.Project) error
	Delete(ctx context.Context, id uint) error
	List(ctx context.Context, filter ProjectFilter) ([]entities.Project, *PaginationResult, error)

	// Project status management
	UpdateStatus(ctx context.Context, id uint, status entities.ProjectStatus) error
	ActivateProject(ctx context.Context, id uint) error
	DeactivateProject(ctx context.Context, id uint) error
	CompleteProject(ctx context.Context, id uint) error
	ArchiveProject(ctx context.Context, id uint) error

	// User management
	AddUser(ctx context.Context, projectID, userID uint) error
	RemoveUser(ctx context.Context, projectID, userID uint) error
	GetProjectUsers(ctx context.Context, projectID uint) ([]entities.User, error)
	GetUserProjects(ctx context.Context, userID uint) ([]entities.Project, error)
	IsUserInProject(ctx context.Context, projectID, userID uint) (bool, error)
	GetAllProjectUsers(ctx context.Context, projectID uint) ([]entities.User, error) // Including group users
	BulkAddUsers(ctx context.Context, projectID uint, userIDs []uint) error
	BulkRemoveUsers(ctx context.Context, projectID uint, userIDs []uint) error
	UpdateUserRole(ctx context.Context, projectID, userID uint, role string) error
	GetUserRole(ctx context.Context, projectID, userID uint) (string, error)

	// Group management
	AddGroup(ctx context.Context, projectID, groupID uint) error
	RemoveGroup(ctx context.Context, projectID, groupID uint) error
	GetProjectGroups(ctx context.Context, projectID uint) ([]entities.Group, error)
	GetGroupProjects(ctx context.Context, groupID uint) ([]entities.Project, error)
	IsGroupInProject(ctx context.Context, projectID, groupID uint) (bool, error)
	BulkAddGroups(ctx context.Context, projectID uint, groupIDs []uint) error
	BulkRemoveGroups(ctx context.Context, projectID uint, groupIDs []uint) error

	// Server management
	AddServer(ctx context.Context, projectID, serverID uint) error
	RemoveServer(ctx context.Context, projectID, serverID uint) error
	GetProjectServers(ctx context.Context, projectID uint) ([]entities.Server, error)
	GetServerProjects(ctx context.Context, serverID uint) ([]entities.Project, error)
	IsServerInProject(ctx context.Context, projectID, serverID uint) (bool, error)
	BulkAddServers(ctx context.Context, projectID uint, serverIDs []uint) error
	BulkRemoveServers(ctx context.Context, projectID uint, serverIDs []uint) error

	// Project filtering and search
	GetByOwner(ctx context.Context, ownerID uint) ([]entities.Project, error)
	GetByStatus(ctx context.Context, status entities.ProjectStatus) ([]entities.Project, error)
	GetByPriority(ctx context.Context, priority entities.ProjectPriority) ([]entities.Project, error)
	GetByDepartment(ctx context.Context, department string) ([]entities.Project, error)
	GetByEnvironment(ctx context.Context, environment string) ([]entities.Project, error)
	GetByDateRange(ctx context.Context, startAfter, endBefore *time.Time) ([]entities.Project, error)
	SearchProjects(ctx context.Context, query string) ([]entities.Project, error)
	GetActiveProjects(ctx context.Context) ([]entities.Project, error)
	GetOverdueProjects(ctx context.Context) ([]entities.Project, error)
	GetOverBudgetProjects(ctx context.Context) ([]entities.Project, error)

	// Project statistics
	GetProjectStats(ctx context.Context, projectID uint) (*ProjectStats, error)
	GetProjectsByStatus(ctx context.Context, status entities.ProjectStatus) ([]entities.Project, error)
	GetProjectsCount(ctx context.Context) (int64, error)
	GetActiveProjectsCount(ctx context.Context) (int64, error)
	GetProjectSummary(ctx context.Context) (*ProjectSummary, error)

	// Budget and financial management
	UpdateBudget(ctx context.Context, projectID uint, budget float64) error
	GetBudgetInfo(ctx context.Context, projectID uint) (*ProjectBudgetInfo, error)
	RecordExpense(ctx context.Context, projectID uint, expense *ProjectExpense) error
	GetProjectExpenses(ctx context.Context, projectID uint, filter ExpenseFilter) ([]ProjectExpense, error)
	GetBudgetSummary(ctx context.Context, projectID uint) (*BudgetSummary, error)

	// Timeline and milestone management
	AddMilestone(ctx context.Context, projectID uint, milestone *ProjectMilestone) error
	UpdateMilestone(ctx context.Context, milestoneID uint, milestone *ProjectMilestone) error
	DeleteMilestone(ctx context.Context, milestoneID uint) error
	GetProjectMilestones(ctx context.Context, projectID uint) ([]ProjectMilestone, error)
	CompleteMilestone(ctx context.Context, milestoneID uint) error
	GetProjectProgress(ctx context.Context, projectID uint) (*ProjectProgress, error)

	// Project activity and analytics
	GetProjectActivity(ctx context.Context, projectID uint, timeRange TimeRange) (*ProjectActivity, error)
	GetProjectMembersActivity(ctx context.Context, projectID uint, timeRange TimeRange) ([]UserActivitySummary, error)
	GetProjectServerActivity(ctx context.Context, projectID uint, timeRange TimeRange) ([]ServerActivitySummary, error)
	GetRecentProjectChanges(ctx context.Context, projectID uint, limit int) ([]ProjectChange, error)

	// Metadata and settings management
	UpdateMetadata(ctx context.Context, projectID uint, metadata entities.ProjectMetadata) error
	UpdateSettings(ctx context.Context, projectID uint, settings entities.ProjectSettings) error
	GetMetadata(ctx context.Context, projectID uint) (*entities.ProjectMetadata, error)
	GetSettings(ctx context.Context, projectID uint) (*entities.ProjectSettings, error)

	// Access control
	GetUserAccessibleProjects(ctx context.Context, userID uint) ([]entities.Project, error)
	CanUserManageProject(ctx context.Context, userID, projectID uint) (bool, error)
	GetProjectAdmins(ctx context.Context, projectID uint) ([]entities.User, error)
	GetProjectOwners(ctx context.Context, projectID uint) ([]entities.User, error)

	// Bulk operations
	BulkCreate(ctx context.Context, projects []entities.Project) error
	BulkUpdate(ctx context.Context, projects []entities.Project) error
	BulkDelete(ctx context.Context, ids []uint) error
	BulkUpdateStatus(ctx context.Context, projectIDs []uint, status entities.ProjectStatus) error
	BulkUpdateOwner(ctx context.Context, projectIDs []uint, ownerID uint) error

	// Project templates and cloning
	CreateTemplate(ctx context.Context, projectID uint, templateName string) (*ProjectTemplate, error)
	CreateFromTemplate(ctx context.Context, templateID uint, projectData *entities.Project) (*entities.Project, error)
	CloneProject(ctx context.Context, projectID uint, newName, newCode string) (*entities.Project, error)
	GetProjectTemplates(ctx context.Context) ([]ProjectTemplate, error)

	// Reporting and analytics
	GetProjectReport(ctx context.Context, projectID uint, reportType string) (*ProjectReport, error)
	GetPortfolioReport(ctx context.Context, filter ProjectFilter) (*PortfolioReport, error)
	GetResourceUtilization(ctx context.Context, projectID uint) (*ResourceUtilization, error)
	GetProjectKPIs(ctx context.Context, projectID uint) (*ProjectKPIs, error)

	// Cleanup operations
	CleanupCompletedProjects(ctx context.Context, olderThanDays int) (int64, error)
	ArchiveOldProjects(ctx context.Context, olderThanDays int) (int64, error)
	RemoveInactiveMembers(ctx context.Context, projectID uint, daysSinceLastActivity int) (int64, error)
}

// ProjectFilter represents project filtering options
type ProjectFilter struct {
	Name         string
	Code         string
	Status       string
	Priority     string
	OwnerID      *uint
	Department   string
	Environment  string
	Search       string
	IsActive     *bool
	IsOverdue    *bool
	IsOverBudget *bool
	StartAfter   *time.Time
	StartBefore  *time.Time
	EndAfter     *time.Time
	EndBefore    *time.Time
	Tags         []string
	UserID       *uint // Filter projects that contain this user
	GroupID      *uint // Filter projects that contain this group
	ServerID     *uint // Filter projects that contain this server
	MinBudget    *float64
	MaxBudget    *float64
	Pagination   PaginationParams
	SortBy       string
	SortOrder    string
}

// ProjectStats represents project statistics
type ProjectStats struct {
	ProjectID           uint               `json:"project_id"`
	ProjectName         string             `json:"project_name"`
	TotalUsers          int64              `json:"total_users"`
	ActiveUsers         int64              `json:"active_users"`
	DirectUsers         int64              `json:"direct_users"`
	GroupUsers          int64              `json:"group_users"`
	TotalGroups         int64              `json:"total_groups"`
	ActiveGroups        int64              `json:"active_groups"`
	TotalServers        int64              `json:"total_servers"`
	ActiveServers       int64              `json:"active_servers"`
	AccessGrants        int64              `json:"access_grants"`
	ActiveSessions      int64              `json:"active_sessions"`
	TotalSessions       int64              `json:"total_sessions"`
	TotalMilestones     int64              `json:"total_milestones"`
	CompletedMilestones int64              `json:"completed_milestones"`
	UsersByRole         map[string]int64   `json:"users_by_role"`
	ServersByEnv        map[string]int64   `json:"servers_by_environment"`
	ServersByPlatform   map[string]int64   `json:"servers_by_platform"`
	LastActivity        *string            `json:"last_activity,omitempty"`
	CreatedAt           string             `json:"created_at"`
	Budget              *ProjectBudgetInfo `json:"budget,omitempty"`
	Progress            *ProjectProgress   `json:"progress,omitempty"`
}

// ProjectSummary represents overall project summary
type ProjectSummary struct {
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
	TotalBudget  float64          `json:"total_budget"`
	TotalSpent   float64          `json:"total_spent"`
}

// ProjectBudgetInfo represents project budget information
type ProjectBudgetInfo struct {
	ProjectID         uint    `json:"project_id"`
	TotalBudget       float64 `json:"total_budget"`
	SpentAmount       float64 `json:"spent_amount"`
	RemainingAmount   float64 `json:"remaining_amount"`
	EncumberedAmount  float64 `json:"encumbered_amount"`
	BurnRate          float64 `json:"burn_rate"`
	ProjectedTotal    float64 `json:"projected_total"`
	IsOverBudget      bool    `json:"is_over_budget"`
	BudgetUtilization float64 `json:"budget_utilization"`
	LastUpdated       string  `json:"last_updated"`
}

// ProjectExpense represents project expense
type ProjectExpense struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	ProjectID   uint      `json:"project_id" gorm:"not null;index"`
	Category    string    `json:"category" gorm:"not null;size:100"`
	Description string    `json:"description" gorm:"not null"`
	Amount      float64   `json:"amount" gorm:"not null"`
	Currency    string    `json:"currency" gorm:"size:3;default:'USD'"`
	Date        time.Time `json:"date" gorm:"not null"`
	SubmittedBy uint      `json:"submitted_by" gorm:"not null"`
	ApprovedBy  *uint     `json:"approved_by"`
	Status      string    `json:"status" gorm:"not null;default:'pending'"`
	ReceiptURL  string    `json:"receipt_url"`
	Tags        []string  `json:"tags" gorm:"type:jsonb"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ExpenseFilter represents expense filtering options
type ExpenseFilter struct {
	Category    string
	Status      string
	SubmittedBy *uint
	ApprovedBy  *uint
	DateFrom    *time.Time
	DateTo      *time.Time
	MinAmount   *float64
	MaxAmount   *float64
	Tags        []string
	Pagination  PaginationParams
	SortBy      string
	SortOrder   string
}

// BudgetSummary represents budget summary
type BudgetSummary struct {
	TotalBudget        float64            `json:"total_budget"`
	TotalSpent         float64            `json:"total_spent"`
	TotalRemaining     float64            `json:"total_remaining"`
	ExpensesByCategory map[string]float64 `json:"expenses_by_category"`
	ExpensesByMonth    []MonthlyExpense   `json:"expenses_by_month"`
	TopExpenses        []ProjectExpense   `json:"top_expenses"`
	PendingExpenses    []ProjectExpense   `json:"pending_expenses"`
	BurnRate           float64            `json:"burn_rate"`
	ProjectedEndDate   *string            `json:"projected_end_date,omitempty"`
}

// MonthlyExpense represents monthly expense data
type MonthlyExpense struct {
	Month  string  `json:"month"`
	Amount float64 `json:"amount"`
	Count  int64   `json:"count"`
	Budget float64 `json:"budget"`
}

// ProjectMilestone represents project milestone
type ProjectMilestone struct {
	ID           uint       `json:"id" gorm:"primaryKey"`
	ProjectID    uint       `json:"project_id" gorm:"not null;index"`
	Name         string     `json:"name" gorm:"not null;size:200"`
	Description  string     `json:"description" gorm:"type:text"`
	DueDate      *time.Time `json:"due_date"`
	CompletedAt  *time.Time `json:"completed_at"`
	Status       string     `json:"status" gorm:"not null;default:'pending'"`
	Progress     float64    `json:"progress" gorm:"default:0"`
	Priority     string     `json:"priority" gorm:"default:'medium'"`
	AssignedTo   *uint      `json:"assigned_to"`
	Dependencies []string   `json:"dependencies" gorm:"type:jsonb"`
	Tags         []string   `json:"tags" gorm:"type:jsonb"`
	CreatedBy    uint       `json:"created_by" gorm:"not null"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// ProjectProgress represents project progress information
type ProjectProgress struct {
	ProjectID           uint            `json:"project_id"`
	Percentage          float64         `json:"percentage"`
	DaysElapsed         int             `json:"days_elapsed"`
	DaysRemaining       int             `json:"days_remaining"`
	TotalDays           int             `json:"total_days"`
	IsOnTrack           bool            `json:"is_on_track"`
	IsOverdue           bool            `json:"is_overdue"`
	CompletionDate      *string         `json:"completion_date,omitempty"`
	MilestonesTotal     int             `json:"milestones_total"`
	MilestonesCompleted int             `json:"milestones_completed"`
	MilestonesOverdue   int             `json:"milestones_overdue"`
	ProgressByPhase     []PhaseProgress `json:"progress_by_phase"`
	RecentAchievements  []string        `json:"recent_achievements"`
	UpcomingDeadlines   []Deadline      `json:"upcoming_deadlines"`
}

// PhaseProgress represents progress by project phase
type PhaseProgress struct {
	Phase      string  `json:"phase"`
	Progress   float64 `json:"progress"`
	IsComplete bool    `json:"is_complete"`
	StartDate  *string `json:"start_date,omitempty"`
	EndDate    *string `json:"end_date,omitempty"`
}

// Deadline represents upcoming deadline
type Deadline struct {
	Name       string `json:"name"`
	DueDate    string `json:"due_date"`
	DaysLeft   int    `json:"days_left"`
	IsOverdue  bool   `json:"is_overdue"`
	Priority   string `json:"priority"`
	AssignedTo string `json:"assigned_to,omitempty"`
}

// ProjectActivity represents project activity information
type ProjectActivity struct {
	ProjectID     uint                  `json:"project_id"`
	ProjectName   string                `json:"project_name"`
	TimeRange     TimeRange             `json:"time_range"`
	UserActivity  []UserActivitySummary `json:"user_activity"`
	ServerAccess  []ServerAccessSummary `json:"server_access"`
	RecentChanges []ProjectChange       `json:"recent_changes"`
	Stats         *ProjectActivityStats `json:"stats"`
	Milestones    []ProjectMilestone    `json:"milestones"`
}

// ProjectChange represents a change in project
type ProjectChange struct {
	ID          uint              `json:"id"`
	ProjectID   uint              `json:"project_id"`
	Type        string            `json:"type"` // member_added, milestone_completed, etc.
	Action      string            `json:"action"`
	Description string            `json:"description"`
	UserID      *uint             `json:"user_id,omitempty"`
	Username    string            `json:"username,omitempty"`
	TargetID    *uint             `json:"target_id,omitempty"`
	TargetType  string            `json:"target_type,omitempty"`
	TargetName  string            `json:"target_name,omitempty"`
	Timestamp   string            `json:"timestamp"`
	IPAddress   string            `json:"ip_address,omitempty"`
	Details     map[string]string `json:"details,omitempty"`
	OldValue    string            `json:"old_value,omitempty"`
	NewValue    string            `json:"new_value,omitempty"`
	Impact      string            `json:"impact,omitempty"`
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
	MilestoneChanges int64 `json:"milestone_changes"`
	ServerChanges    int64 `json:"server_changes"`
}

// ProjectTemplate represents project template
type ProjectTemplate struct {
	ID          uint                `json:"id" gorm:"primaryKey"`
	Name        string              `json:"name" gorm:"not null;size:200"`
	Description string              `json:"description" gorm:"type:text"`
	Category    string              `json:"category" gorm:"size:100"`
	IsPublic    bool                `json:"is_public" gorm:"default:false"`
	CreatedBy   uint                `json:"created_by" gorm:"not null"`
	UsageCount  int64               `json:"usage_count" gorm:"default:0"`
	Template    ProjectTemplateData `json:"template" gorm:"type:jsonb"`
	Tags        []string            `json:"tags" gorm:"type:jsonb"`
	CreatedAt   time.Time           `json:"created_at"`
	UpdatedAt   time.Time           `json:"updated_at"`
}

// ProjectTemplateData represents template data structure
type ProjectTemplateData struct {
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	Priority    entities.ProjectPriority `json:"priority"`
	Duration    int                      `json:"duration"` // in days
	Budget      float64                  `json:"budget"`
	Metadata    entities.ProjectMetadata `json:"metadata"`
	Settings    entities.ProjectSettings `json:"settings"`
	Milestones  []MilestoneTemplate      `json:"milestones"`
	Roles       []RoleTemplate           `json:"roles"`
	DefaultTags []string                 `json:"default_tags"`
}

// MilestoneTemplate represents milestone template
type MilestoneTemplate struct {
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	DaysFromStart int      `json:"days_from_start"`
	Priority      string   `json:"priority"`
	Dependencies  []string `json:"dependencies"`
}

// RoleTemplate represents role template
type RoleTemplate struct {
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	IsRequired  bool     `json:"is_required"`
}

// ProjectReport represents project report
type ProjectReport struct {
	ProjectID       uint                `json:"project_id"`
	ProjectName     string              `json:"project_name"`
	ReportType      string              `json:"report_type"`
	TimeRange       TimeRange           `json:"time_range"`
	Summary         *ProjectStats       `json:"summary"`
	Activity        *ProjectActivity    `json:"activity"`
	Budget          *BudgetSummary      `json:"budget"`
	Progress        *ProjectProgress    `json:"progress"`
	Members         []ProjectMemberInfo `json:"members"`
	Servers         []ProjectServerInfo `json:"servers"`
	Milestones      []ProjectMilestone  `json:"milestones"`
	Risks           []ProjectRisk       `json:"risks"`
	Recommendations []string            `json:"recommendations"`
	GeneratedAt     string              `json:"generated_at"`
	GeneratedBy     string              `json:"generated_by"`
}

// ProjectMemberInfo represents project member information
type ProjectMemberInfo struct {
	UserID       uint                `json:"user_id"`
	Username     string              `json:"username"`
	FullName     string              `json:"full_name"`
	Email        string              `json:"email"`
	Role         string              `json:"role"`
	Department   string              `json:"department"`
	JoinedAt     string              `json:"joined_at"`
	LastActivity *string             `json:"last_activity,omitempty"`
	IsActive     bool                `json:"is_active"`
	Contribution *MemberContribution `json:"contribution,omitempty"`
}

// MemberContribution represents member contribution metrics
type MemberContribution struct {
	TotalSessions     int64   `json:"total_sessions"`
	TotalCommands     int64   `json:"total_commands"`
	TotalTime         int64   `json:"total_time"`
	ServersAccessed   int64   `json:"servers_accessed"`
	ContributionScore float64 `json:"contribution_score"`
}

// ProjectServerInfo represents project server information
type ProjectServerInfo struct {
	ServerID    uint         `json:"server_id"`
	Name        string       `json:"name"`
	IP          string       `json:"ip"`
	Environment string       `json:"environment"`
	Platform    string       `json:"platform"`
	Status      string       `json:"status"`
	AddedAt     string       `json:"added_at"`
	Usage       *ServerUsage `json:"usage,omitempty"`
}

// ServerUsage represents server usage metrics
type ServerUsage struct {
	TotalSessions     int64   `json:"total_sessions"`
	ActiveSessions    int64   `json:"active_sessions"`
	TotalCommands     int64   `json:"total_commands"`
	TotalDataTransfer int64   `json:"total_data_transfer"`
	UniqueUsers       int64   `json:"unique_users"`
	UtilizationScore  float64 `json:"utilization_score"`
}

// ProjectRisk represents project risk
type ProjectRisk struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Probability string `json:"probability"`
	Impact      string `json:"impact"`
	Mitigation  string `json:"mitigation"`
	Owner       string `json:"owner"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// PortfolioReport represents portfolio report
type PortfolioReport struct {
	TimeRange           TimeRange                     `json:"time_range"`
	Summary             *ProjectSummary               `json:"summary"`
	Projects            []ProjectStats                `json:"projects"`
	TopPerformers       []ProjectStats                `json:"top_performers"`
	AtRiskProjects      []ProjectStats                `json:"at_risk_projects"`
	ResourceUtilization *PortfolioResourceUtilization `json:"resource_utilization"`
	BudgetAnalysis      *PortfolioBudgetAnalysis      `json:"budget_analysis"`
	Trends              []PortfolioTrend              `json:"trends"`
	Recommendations     []string                      `json:"recommendations"`
	GeneratedAt         string                        `json:"generated_at"`
}

// PortfolioResourceUtilization represents portfolio resource utilization
type PortfolioResourceUtilization struct {
	TotalUsers           int64              `json:"total_users"`
	ActiveUsers          int64              `json:"active_users"`
	TotalServers         int64              `json:"total_servers"`
	ActiveServers        int64              `json:"active_servers"`
	UserUtilization      float64            `json:"user_utilization"`
	ServerUtilization    float64            `json:"server_utilization"`
	UtilizationByProject map[string]float64 `json:"utilization_by_project"`
}

// PortfolioBudgetAnalysis represents portfolio budget analysis
type PortfolioBudgetAnalysis struct {
	TotalBudget      float64            `json:"total_budget"`
	TotalSpent       float64            `json:"total_spent"`
	TotalRemaining   float64            `json:"total_remaining"`
	OverBudgetCount  int64              `json:"over_budget_count"`
	UnderBudgetCount int64              `json:"under_budget_count"`
	AverageBurnRate  float64            `json:"average_burn_rate"`
	BudgetByPriority map[string]float64 `json:"budget_by_priority"`
	SpendByCategory  map[string]float64 `json:"spend_by_category"`
}

// PortfolioTrend represents portfolio trend data
type PortfolioTrend struct {
	Period            string  `json:"period"`
	ActiveProjects    int64   `json:"active_projects"`
	CompletedProjects int64   `json:"completed_projects"`
	TotalBudget       float64 `json:"total_budget"`
	TotalSpent        float64 `json:"total_spent"`
	NewProjects       int64   `json:"new_projects"`
	CancelledProjects int64   `json:"cancelled_projects"`
}

// ResourceUtilization represents resource utilization
type ResourceUtilization struct {
	ProjectID         uint     `json:"project_id"`
	UserUtilization   float64  `json:"user_utilization"`
	ServerUtilization float64  `json:"server_utilization"`
	BudgetUtilization float64  `json:"budget_utilization"`
	TimeUtilization   float64  `json:"time_utilization"`
	OverallScore      float64  `json:"overall_score"`
	Bottlenecks       []string `json:"bottlenecks"`
	Recommendations   []string `json:"recommendations"`
}

// ProjectKPIs represents project key performance indicators
type ProjectKPIs struct {
	ProjectID               uint           `json:"project_id"`
	SchedulePerformance     float64        `json:"schedule_performance"` // SPI
	CostPerformance         float64        `json:"cost_performance"`     // CPI
	QualityScore            float64        `json:"quality_score"`
	TeamProductivity        float64        `json:"team_productivity"`
	StakeholderSatisfaction float64        `json:"stakeholder_satisfaction"`
	RiskScore               float64        `json:"risk_score"`
	OverallHealth           string         `json:"overall_health"`
	Trends                  []KPITrend     `json:"trends"`
	Benchmarks              *KPIBenchmarks `json:"benchmarks"`
}

// KPITrend represents KPI trend data
type KPITrend struct {
	Period       string  `json:"period"`
	SPI          float64 `json:"spi"`
	CPI          float64 `json:"cpi"`
	Quality      float64 `json:"quality"`
	Productivity float64 `json:"productivity"`
}

// KPIBenchmarks represents KPI benchmarks
type KPIBenchmarks struct {
	IndustryAverage     *ProjectKPIs `json:"industry_average"`
	OrganizationAverage *ProjectKPIs `json:"organization_average"`
	BestInClass         *ProjectKPIs `json:"best_in_class"`
}
