package entities

import (
	"time"

	"gorm.io/gorm"
)

type Group struct {
	ID          uint             `json:"id" gorm:"primaryKey"`
	Name        string           `json:"name" gorm:"uniqueIndex;not null;size:100"`
	Description string           `json:"description" gorm:"type:text"`
	Type        GroupType        `json:"type" gorm:"not null;type:varchar(20);default:'department'"`
	ParentID    *uint            `json:"parent_id" gorm:"index"`
	Parent      *Group           `json:"parent,omitempty" gorm:"foreignKey:ParentID"`
	Children    []Group          `json:"children,omitempty" gorm:"foreignKey:ParentID"`
	Users       []User           `json:"users" gorm:"many2many:user_groups;"`
	Servers     []Server         `json:"servers" gorm:"many2many:server_groups;"`
	Projects    []Project        `json:"projects" gorm:"many2many:group_projects;"`
	Permissions GroupPermissions `json:"permissions" gorm:"type:jsonb"`
	IsActive    bool             `json:"is_active" gorm:"default:true"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
	DeletedAt   gorm.DeletedAt   `json:"-" gorm:"index"`
}

// GroupType represents group type
type GroupType string

const (
	GroupTypeDepartment GroupType = "department"
	GroupTypeTeam       GroupType = "team"
	GroupTypeProject    GroupType = "project"
	GroupTypeRole       GroupType = "role"
)

// GroupPermissions represents group permissions
type GroupPermissions struct {
	CanCreateServers bool `json:"can_create_servers"`
	CanDeleteServers bool `json:"can_delete_servers"`
	CanManageUsers   bool `json:"can_manage_users"`
	CanGrantAccess   bool `json:"can_grant_access"`
	CanRevokeAccess  bool `json:"can_revoke_access"`
	CanViewAuditLog  bool `json:"can_view_audit_log"`
}

// TableName sets the table name for Group
func (Group) TableName() string {
	return "groups"
}

// BeforeCreate hook to set default values
func (g *Group) BeforeCreate(tx *gorm.DB) error {
	if g.Type == "" {
		g.Type = GroupTypeDepartment
	}
	if !g.IsActive {
		g.IsActive = true
	}
	return nil
}

// IsActive checks if group is active
func (g *Group) IsActiveGroup() bool {
	return g.IsActive
}

// HasParent checks if group has a parent
func (g *Group) HasParent() bool {
	return g.ParentID != nil
}

// HasChildren checks if group has children
func (g *Group) HasChildren() bool {
	return len(g.Children) > 0
}

// AddUser adds a user to the group
func (g *Group) AddUser(user User) {
	g.Users = append(g.Users, user)
}

// RemoveUser removes a user from the group
func (g *Group) RemoveUser(userID uint) {
	for i, user := range g.Users {
		if user.ID == userID {
			g.Users = append(g.Users[:i], g.Users[i+1:]...)
			break
		}
	}
}

// HasUser checks if user is in the group
func (g *Group) HasUser(userID uint) bool {
	for _, user := range g.Users {
		if user.ID == userID {
			return true
		}
	}
	return false
}

// AddServer adds a server to the group
func (g *Group) AddServer(server Server) {
	g.Servers = append(g.Servers, server)
}

// RemoveServer removes a server from the group
func (g *Group) RemoveServer(serverID uint) {
	for i, server := range g.Servers {
		if server.ID == serverID {
			g.Servers = append(g.Servers[:i], g.Servers[i+1:]...)
			break
		}
	}
}

// HasServer checks if server is in the group
func (g *Group) HasServer(serverID uint) bool {
	for _, server := range g.Servers {
		if server.ID == serverID {
			return true
		}
	}
	return false
}

// GetAllUsers returns all users including from child groups
func (g *Group) GetAllUsers() []User {
	allUsers := make(map[uint]User)

	// Add users from current group
	for _, user := range g.Users {
		allUsers[user.ID] = user
	}

	// Add users from child groups
	for _, child := range g.Children {
		childUsers := child.GetAllUsers()
		for _, user := range childUsers {
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

// GetAllServers returns all servers including from child groups
func (g *Group) GetAllServers() []Server {
	allServers := make(map[uint]Server)

	// Add servers from current group
	for _, server := range g.Servers {
		allServers[server.ID] = server
	}

	// Add servers from child groups
	for _, child := range g.Children {
		childServers := child.GetAllServers()
		for _, server := range childServers {
			allServers[server.ID] = server
		}
	}

	// Convert map to slice
	servers := make([]Server, 0, len(allServers))
	for _, server := range allServers {
		servers = append(servers, server)
	}

	return servers
}

// CanPerformAction checks if group has specific permission
func (g *Group) CanPerformAction(action string) bool {
	switch action {
	case "create_servers":
		return g.Permissions.CanCreateServers
	case "delete_servers":
		return g.Permissions.CanDeleteServers
	case "manage_users":
		return g.Permissions.CanManageUsers
	case "grant_access":
		return g.Permissions.CanGrantAccess
	case "revoke_access":
		return g.Permissions.CanRevokeAccess
	case "view_audit_log":
		return g.Permissions.CanViewAuditLog
	default:
		return false
	}
}

// ValidateGroup validates group data
func (g *Group) ValidateGroup() error {
	if g.Name == "" {
		return ErrInvalidGroupName
	}

	// Check for circular dependency in parent-child relationship
	if g.ParentID != nil && *g.ParentID == g.ID {
		return ErrCircularGroupDependency
	}

	return nil
}

// GetPath returns the full path of the group (parent.child.grandchild)
func (g *Group) GetPath() string {
	if g.Parent == nil {
		return g.Name
	}
	return g.Parent.GetPath() + "." + g.Name
}

// GetLevel returns the level of the group in hierarchy (0 for root)
func (g *Group) GetLevel() int {
	if g.Parent == nil {
		return 0
	}
	return g.Parent.GetLevel() + 1
}
