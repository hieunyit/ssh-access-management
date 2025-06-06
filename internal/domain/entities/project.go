package entities

import (
	"time"

	"gorm.io/gorm"
)

type Project struct {
	ID          uint            `json:"id" gorm:"primaryKey"`
	Name        string          `json:"name" gorm:"uniqueIndex;not null;size:100"`
	Code        string          `json:"code" gorm:"uniqueIndex;not null;size:20"` // Short project code
	Description string          `json:"description" gorm:"type:text"`
	Status      ProjectStatus   `json:"status" gorm:"not null;type:varchar(20);default:'active'"`
	Priority    ProjectPriority `json:"priority" gorm:"not null;type:varchar(20);default:'medium'"`
	StartDate   *time.Time      `json:"start_date"`
	EndDate     *time.Time      `json:"end_date"`
	Budget      float64         `json:"budget" gorm:"type:decimal(12,2)"`
	OwnerID     uint            `json:"owner_id" gorm:"not null;index"`
	Owner       User            `json:"owner" gorm:"foreignKey:OwnerID"`
	Users       []User          `json:"users" gorm:"many2many:user_projects;"`
	Groups      []Group         `json:"groups" gorm:"many2many:group_projects;"`
	Servers     []Server        `json:"servers" gorm:"many2many:server_projects;"`
	Metadata    ProjectMetadata `json:"metadata" gorm:"type:jsonb"`
	Settings    ProjectSettings `json:"settings" gorm:"type:jsonb"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	DeletedAt   gorm.DeletedAt  `json:"-" gorm:"index"`
}

// ProjectStatus represents project status
type ProjectStatus string

const (
	ProjectStatusActive    ProjectStatus = "active"
	ProjectStatusInactive  ProjectStatus = "inactive"
	ProjectStatusCompleted ProjectStatus = "completed"
	ProjectStatusArchived  ProjectStatus = "archived"
)

// ProjectPriority represents project priority
type ProjectPriority string

const (
	ProjectPriorityLow      ProjectPriority = "low"
	ProjectPriorityMedium   ProjectPriority = "medium"
	ProjectPriorityHigh     ProjectPriority = "high"
	ProjectPriorityCritical ProjectPriority = "critical"
)

// ProjectMetadata represents project metadata
type ProjectMetadata struct {
	Department   string            `json:"department"`
	CostCenter   string            `json:"cost_center"`
	Environment  string            `json:"environment"`
	Tags         []string          `json:"tags"`
	ExternalID   string            `json:"external_id"`   // External system ID
	JiraProject  string            `json:"jira_project"`  // JIRA project key
	GitRepo      string            `json:"git_repo"`      // Git repository URL
	SlackChannel string            `json:"slack_channel"` // Slack channel
	CustomFields map[string]string `json:"custom_fields"`
}

// ProjectSettings represents project settings
type ProjectSettings struct {
	AutoApproval        bool                 `json:"auto_approval"`        // Auto approve access requests
	RequireApproval     bool                 `json:"require_approval"`     // Require approval for access
	MaxAccessDuration   int                  `json:"max_access_duration"`  // Max access duration in hours
	AllowedEnvironments []string             `json:"allowed_environments"` // Allowed environments
	AccessPolicies      []AccessPolicy       `json:"access_policies"`      // Access policies
	Notifications       NotificationSettings `json:"notifications"`        // Notification settings
}

// AccessPolicy represents access policy
type AccessPolicy struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Conditions  []string `json:"conditions"` // Conditions for the policy
	Actions     []string `json:"actions"`    // Allowed actions
	Resources   []string `json:"resources"`  // Resources the policy applies to
}

// NotificationSettings represents notification settings
type NotificationSettings struct {
	Email bool `json:"email"`
	Slack bool `json:"slack"`
	Teams bool `json:"teams"`
}

// TableName sets the table name for Project
func (Project) TableName() string {
	return "projects"
}

// BeforeCreate hook to set default values
func (p *Project) BeforeCreate(tx *gorm.DB) error {
	if p.Status == "" {
		p.Status = ProjectStatusActive
	}
	if p.Priority == "" {
		p.Priority = ProjectPriorityMedium
	}
	return nil
}

// IsActive checks if project is active
func (p *Project) IsActive() bool {
	return p.Status == ProjectStatusActive
}

// IsCompleted checks if project is completed
func (p *Project) IsCompleted() bool {
	return p.Status == ProjectStatusCompleted
}

// IsArchived checks if project is archived
func (p *Project) IsArchived() bool {
	return p.Status == ProjectStatusArchived
}

// HasUser checks if user is assigned to the project
func (p *Project) HasUser(userID uint) bool {
	for _, user := range p.Users {
		if user.ID == userID {
			return true
		}
	}
	return false
}

// HasGroup checks if group is assigned to the project
func (p *Project) HasGroup(groupID uint) bool {
	for _, group := range p.Groups {
		if group.ID == groupID {
			return true
		}
	}
	return false
}

// HasServer checks if server is assigned to the project
func (p *Project) HasServer(serverID uint) bool {
	for _, server := range p.Servers {
		if server.ID == serverID {
			return true
		}
	}
	return false
}

// AddUser adds a user to the project
func (p *Project) AddUser(user User) {
	if !p.HasUser(user.ID) {
		p.Users = append(p.Users, user)
	}
}

// RemoveUser removes a user from the project
func (p *Project) RemoveUser(userID uint) {
	for i, user := range p.Users {
		if user.ID == userID {
			p.Users = append(p.Users[:i], p.Users[i+1:]...)
			break
		}
	}
}

// AddGroup adds a group to the project
func (p *Project) AddGroup(group Group) {
	if !p.HasGroup(group.ID) {
		p.Groups = append(p.Groups, group)
	}
}

// RemoveGroup removes a group from the project
func (p *Project) RemoveGroup(groupID uint) {
	for i, group := range p.Groups {
		if group.ID == groupID {
			p.Groups = append(p.Groups[:i], p.Groups[i+1:]...)
			break
		}
	}
}

// AddServer adds a server to the project
func (p *Project) AddServer(server Server) {
	if !p.HasServer(server.ID) {
		p.Servers = append(p.Servers, server)
	}
}

// RemoveServer removes a server from the project
func (p *Project) RemoveServer(serverID uint) {
	for i, server := range p.Servers {
		if server.ID == serverID {
			p.Servers = append(p.Servers[:i], p.Servers[i+1:]...)
			break
		}
	}
}

// GetAllUsers returns all users including from groups
func (p *Project) GetAllUsers() []User {
	allUsers := make(map[uint]User)

	// Add direct users
	for _, user := range p.Users {
		allUsers[user.ID] = user
	}

	// Add users from groups
	for _, group := range p.Groups {
		for _, user := range group.Users {
			allUsers[user.ID] = user
		}
	}

	// Convert map to slice
	users := make([]User, 0, len(allUsers))
	for _, user := range allUsers {
		users = append(users, user)
	}

	return users
}

// IsOwner checks if user is the project owner
func (p *Project) IsOwner(userID uint) bool {
	return p.OwnerID == userID
}

// IsOverBudget checks if project is over budget
func (p *Project) IsOverBudget(currentSpend float64) bool {
	return p.Budget > 0 && currentSpend > p.Budget
}

// IsOverdue checks if project is overdue
func (p *Project) IsOverdue() bool {
	return p.EndDate != nil && p.EndDate.Before(time.Now()) && !p.IsCompleted()
}

// GetDaysRemaining returns days remaining until project end date
func (p *Project) GetDaysRemaining() int {
	if p.EndDate == nil {
		return -1 // No end date set
	}

	days := int(time.Until(*p.EndDate).Hours() / 24)
	if days < 0 {
		return 0
	}
	return days
}

// GetDuration returns project duration in days
func (p *Project) GetDuration() int {
	if p.StartDate == nil || p.EndDate == nil {
		return 0
	}
	return int(p.EndDate.Sub(*p.StartDate).Hours() / 24)
}

// ValidateProject validates project data
func (p *Project) ValidateProject() error {
	if p.Name == "" {
		return ErrInvalidProjectName
	}
	if p.Code == "" {
		return ErrInvalidProjectCode
	}
	if p.OwnerID == 0 {
		return ErrInvalidProjectOwner
	}

	// Validate date consistency
	if p.StartDate != nil && p.EndDate != nil && p.EndDate.Before(*p.StartDate) {
		return ErrInvalidProjectDates
	}

	return nil
}
