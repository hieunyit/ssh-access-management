package repositories

import (
	"context"
	"ssh-access-management/internal/domain/entities"
)

// GroupRepository defines group repository interface
type GroupRepository interface {
	// Group CRUD operations
	Create(ctx context.Context, group *entities.Group) error
	GetByID(ctx context.Context, id uint) (*entities.Group, error)
	GetByName(ctx context.Context, name string) (*entities.Group, error)
	Update(ctx context.Context, group *entities.Group) error
	Delete(ctx context.Context, id uint) error
	List(ctx context.Context, filter GroupFilter) ([]entities.Group, *PaginationResult, error)

	// Group hierarchy operations
	GetChildren(ctx context.Context, parentID uint) ([]entities.Group, error)
	GetParent(ctx context.Context, groupID uint) (*entities.Group, error)
	GetAncestors(ctx context.Context, groupID uint) ([]entities.Group, error)
	GetDescendants(ctx context.Context, groupID uint) ([]entities.Group, error)
	GetTree(ctx context.Context, rootID *uint) ([]GroupHierarchy, error)
	GetGroupPath(ctx context.Context, groupID uint) (string, error)
	GetGroupLevel(ctx context.Context, groupID uint) (int, error)
	ValidateHierarchy(ctx context.Context, groupID, parentID uint) error

	// Group status management
	Activate(ctx context.Context, id uint) error
	Deactivate(ctx context.Context, id uint) error
	UpdateStatus(ctx context.Context, id uint, isActive bool) error

	// User management
	AddUser(ctx context.Context, groupID, userID uint) error
	RemoveUser(ctx context.Context, groupID, userID uint) error
	GetGroupUsers(ctx context.Context, groupID uint) ([]entities.User, error)
	GetUserGroups(ctx context.Context, userID uint) ([]entities.Group, error)
	IsUserInGroup(ctx context.Context, groupID, userID uint) (bool, error)
	GetAllGroupUsers(ctx context.Context, groupID uint) ([]entities.User, error) // Including child groups
	BulkAddUsers(ctx context.Context, groupID uint, userIDs []uint) error
	BulkRemoveUsers(ctx context.Context, groupID uint, userIDs []uint) error

	// Server management
	AddServer(ctx context.Context, groupID, serverID uint) error
	RemoveServer(ctx context.Context, groupID, serverID uint) error
	GetGroupServers(ctx context.Context, groupID uint) ([]entities.Server, error)
	GetServerGroups(ctx context.Context, serverID uint) ([]entities.Group, error)
	IsServerInGroup(ctx context.Context, groupID, serverID uint) (bool, error)
	GetAllGroupServers(ctx context.Context, groupID uint) ([]entities.Server, error) // Including child groups
	BulkAddServers(ctx context.Context, groupID uint, serverIDs []uint) error
	BulkRemoveServers(ctx context.Context, groupID uint, serverIDs []uint) error

	// Project management
	AddProject(ctx context.Context, groupID, projectID uint) error
	RemoveProject(ctx context.Context, groupID, projectID uint) error
	GetGroupProjects(ctx context.Context, groupID uint) ([]entities.Project, error)
	GetProjectGroups(ctx context.Context, projectID uint) ([]entities.Group, error)
	IsProjectInGroup(ctx context.Context, groupID, projectID uint) (bool, error)
	BulkAddProjects(ctx context.Context, groupID uint, projectIDs []uint) error
	BulkRemoveProjects(ctx context.Context, groupID uint, projectIDs []uint) error

	// Group filtering and search
	GetByType(ctx context.Context, groupType entities.GroupType) ([]entities.Group, error)
	GetByParent(ctx context.Context, parentID *uint) ([]entities.Group, error)
	SearchGroups(ctx context.Context, query string) ([]entities.Group, error)
	GetActiveGroups(ctx context.Context) ([]entities.Group, error)
	GetRootGroups(ctx context.Context) ([]entities.Group, error) // Groups without parent

	// Permission management
	UpdatePermissions(ctx context.Context, groupID uint, permissions entities.GroupPermissions) error
	GetPermissions(ctx context.Context, groupID uint) (*entities.GroupPermissions, error)
	GetEffectivePermissions(ctx context.Context, groupID uint) (*entities.GroupPermissions, error) // Including inherited

	// Group statistics
	GetGroupStats(ctx context.Context, groupID uint) (*GroupStats, error)
	GetGroupsByStatus(ctx context.Context, isActive bool) ([]entities.Group, error)
	GetGroupsCount(ctx context.Context) (int64, error)
	GetActiveGroupsCount(ctx context.Context) (int64, error)
	GetGroupSummary(ctx context.Context) (*GroupSummary, error)

	// Group activity and analytics
	GetGroupActivity(ctx context.Context, groupID uint, timeRange TimeRange) (*GroupActivity, error)
	GetGroupMembersActivity(ctx context.Context, groupID uint, timeRange TimeRange) ([]UserActivitySummary, error)
	GetGroupServerActivity(ctx context.Context, groupID uint, timeRange TimeRange) ([]ServerActivitySummary, error)
	GetRecentGroupChanges(ctx context.Context, groupID uint, limit int) ([]GroupChange, error)

	// Bulk operations
	BulkCreate(ctx context.Context, groups []entities.Group) error
	BulkUpdate(ctx context.Context, groups []entities.Group) error
	BulkDelete(ctx context.Context, ids []uint) error
	BulkUpdateStatus(ctx context.Context, groupIDs []uint, isActive bool) error
	BulkUpdatePermissions(ctx context.Context, groupIDs []uint, permissions entities.GroupPermissions) error

	// Group membership operations
	TransferUsers(ctx context.Context, fromGroupID, toGroupID uint, userIDs []uint) error
	MergeGroups(ctx context.Context, sourceGroupID, targetGroupID uint) error
	SplitGroup(ctx context.Context, groupID uint, newGroupName string, userIDs []uint) (*entities.Group, error)
	CloneGroup(ctx context.Context, groupID uint, newGroupName string, includeUsers bool) (*entities.Group, error)

	// Access control
	GetUserAccessibleGroups(ctx context.Context, userID uint) ([]entities.Group, error)
	CanUserManageGroup(ctx context.Context, userID, groupID uint) (bool, error)
	GetGroupAdmins(ctx context.Context, groupID uint) ([]entities.User, error)

	// Cleanup operations
	CleanupEmptyGroups(ctx context.Context) (int64, error)
	RemoveInactiveUsers(ctx context.Context, groupID uint, daysSinceLastLogin int) (int64, error)
}

// GroupFilter represents group filtering options
type GroupFilter struct {
	Name        string
	Type        string
	ParentID    *uint
	IsActive    *bool
	Search      string
	HasUsers    *bool
	HasServers  *bool
	HasProjects *bool
	Level       *int
	UserID      *uint // Filter groups that contain this user
	ServerID    *uint // Filter groups that contain this server
	ProjectID   *uint // Filter groups that contain this project
	Pagination  PaginationParams
	SortBy      string
	SortOrder   string
}

// GroupHierarchy represents group hierarchy structure
type GroupHierarchy struct {
	ID          uint             `json:"id"`
	Name        string           `json:"name"`
	Type        string           `json:"type"`
	Level       int              `json:"level"`
	Path        string           `json:"path"`
	IsActive    bool             `json:"is_active"`
	UserCount   int64            `json:"user_count"`
	ServerCount int64            `json:"server_count"`
	Children    []GroupHierarchy `json:"children,omitempty"`
	ParentID    *uint            `json:"parent_id,omitempty"`
}

// GroupStats represents group statistics
type GroupStats struct {
	GroupID           uint             `json:"group_id"`
	GroupName         string           `json:"group_name"`
	TotalUsers        int64            `json:"total_users"`
	ActiveUsers       int64            `json:"active_users"`
	InactiveUsers     int64            `json:"inactive_users"`
	TotalServers      int64            `json:"total_servers"`
	ActiveServers     int64            `json:"active_servers"`
	TotalProjects     int64            `json:"total_projects"`
	ActiveProjects    int64            `json:"active_projects"`
	DirectChildren    int64            `json:"direct_children"`
	TotalDescendants  int64            `json:"total_descendants"`
	AccessGrants      int64            `json:"access_grants"`
	ActiveSessions    int64            `json:"active_sessions"`
	UsersByRole       map[string]int64 `json:"users_by_role"`
	ServersByPlatform map[string]int64 `json:"servers_by_platform"`
	ServersByEnv      map[string]int64 `json:"servers_by_environment"`
	LastActivity      *string          `json:"last_activity,omitempty"`
	CreatedAt         string           `json:"created_at"`
}

// GroupSummary represents overall group summary
type GroupSummary struct {
	Total        int64            `json:"total"`
	Active       int64            `json:"active"`
	Inactive     int64            `json:"inactive"`
	ByType       map[string]int64 `json:"by_type"`
	WithUsers    int64            `json:"with_users"`
	WithServers  int64            `json:"with_servers"`
	WithProjects int64            `json:"with_projects"`
	RootGroups   int64            `json:"root_groups"`
	MaxDepth     int              `json:"max_depth"`
	AvgChildren  float64          `json:"avg_children"`
}

// GroupActivity represents group activity information
type GroupActivity struct {
	GroupID       uint                  `json:"group_id"`
	GroupName     string                `json:"group_name"`
	TimeRange     TimeRange             `json:"time_range"`
	UserActivity  []UserActivitySummary `json:"user_activity"`
	ServerAccess  []ServerAccessSummary `json:"server_access"`
	RecentChanges []GroupChange         `json:"recent_changes"`
	Stats         *GroupActivityStats   `json:"stats"`
}

// GroupChange represents a change in group
type GroupChange struct {
	ID          uint              `json:"id"`
	GroupID     uint              `json:"group_id"`
	Type        string            `json:"type"` // member_added, member_removed, permission_changed, etc.
	Action      string            `json:"action"`
	Description string            `json:"description"`
	UserID      *uint             `json:"user_id,omitempty"`
	Username    string            `json:"username,omitempty"`
	TargetID    *uint             `json:"target_id,omitempty"`   // ID of affected user/server/project
	TargetType  string            `json:"target_type,omitempty"` // user, server, project
	TargetName  string            `json:"target_name,omitempty"`
	Timestamp   string            `json:"timestamp"`
	IPAddress   string            `json:"ip_address,omitempty"`
	Details     map[string]string `json:"details,omitempty"`
	OldValue    string            `json:"old_value,omitempty"`
	NewValue    string            `json:"new_value,omitempty"`
}

// GroupActivityStats represents group activity statistics
type GroupActivityStats struct {
	TotalActions      int64 `json:"total_actions"`
	TotalConnections  int64 `json:"total_connections"`
	ActiveUsers       int64 `json:"active_users"`
	ActiveServers     int64 `json:"active_servers"`
	NewMembers        int64 `json:"new_members"`
	RemovedMembers    int64 `json:"removed_members"`
	PermissionChanges int64 `json:"permission_changes"`
	ServerChanges     int64 `json:"server_changes"`
	ProjectChanges    int64 `json:"project_changes"`
}

// GroupMembership represents group membership details
type GroupMembership struct {
	GroupID       uint   `json:"group_id"`
	GroupName     string `json:"group_name"`
	GroupType     string `json:"group_type"`
	UserID        uint   `json:"user_id"`
	Username      string `json:"username"`
	JoinedAt      string `json:"joined_at"`
	Role          string `json:"role"`
	IsActive      bool   `json:"is_active"`
	IsInherited   bool   `json:"is_inherited"` // If membership is through parent group
	InheritedFrom *uint  `json:"inherited_from,omitempty"`
}

// GroupAccess represents group access information
type GroupAccess struct {
	GroupID     uint    `json:"group_id"`
	GroupName   string  `json:"group_name"`
	ServerID    uint    `json:"server_id"`
	ServerName  string  `json:"server_name"`
	ServerIP    string  `json:"server_ip"`
	Environment string  `json:"environment"`
	AccessRole  string  `json:"access_role"`
	GrantedAt   string  `json:"granted_at"`
	GrantedBy   string  `json:"granted_by"`
	ExpiresAt   *string `json:"expires_at,omitempty"`
	IsActive    bool    `json:"is_active"`
	UsageCount  int     `json:"usage_count"`
	LastUsed    *string `json:"last_used,omitempty"`
}

// GroupMemberInfo represents detailed member information
type GroupMemberInfo struct {
	UserID         uint    `json:"user_id"`
	Username       string  `json:"username"`
	FullName       string  `json:"full_name"`
	Email          string  `json:"email"`
	Role           string  `json:"role"`
	Department     string  `json:"department"`
	Status         string  `json:"status"`
	JoinedAt       string  `json:"joined_at"`
	LastActivity   *string `json:"last_activity,omitempty"`
	IsActive       bool    `json:"is_active"`
	IsDirectMember bool    `json:"is_direct_member"`
	InheritedFrom  *uint   `json:"inherited_from,omitempty"`
}

// GroupServerInfo represents server information in group context
type GroupServerInfo struct {
	ServerID    uint   `json:"server_id"`
	Name        string `json:"name"`
	IP          string `json:"ip"`
	Hostname    string `json:"hostname"`
	Environment string `json:"environment"`
	Platform    string `json:"platform"`
	Status      string `json:"status"`
	AddedAt     string `json:"added_at"`
	AddedBy     string `json:"added_by"`
	IsActive    bool   `json:"is_active"`
}

// GroupProjectInfo represents project information in group context
type GroupProjectInfo struct {
	ProjectID   uint   `json:"project_id"`
	Name        string `json:"name"`
	Code        string `json:"code"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Priority    string `json:"priority"`
	AddedAt     string `json:"added_at"`
	AddedBy     string `json:"added_by"`
	IsActive    bool   `json:"is_active"`
}

// GroupDashboard represents group dashboard data
type GroupDashboard struct {
	Group          *entities.Group       `json:"group"`
	Stats          *GroupStats           `json:"stats"`
	RecentActivity []GroupChange         `json:"recent_activity"`
	TopUsers       []UserActivitySummary `json:"top_users"`
	TopServers     []ServerAccessSummary `json:"top_servers"`
	Alerts         []GroupAlert          `json:"alerts"`
	Hierarchy      *GroupHierarchy       `json:"hierarchy"`
	UpdatedAt      string                `json:"updated_at"`
}

// GroupAlert represents group alert/notification
type GroupAlert struct {
	ID        string                 `json:"id"`
	GroupID   uint                   `json:"group_id"`
	Type      string                 `json:"type"`
	Severity  string                 `json:"severity"`
	Title     string                 `json:"title"`
	Message   string                 `json:"message"`
	CreatedAt string                 `json:"created_at"`
	IsRead    bool                   `json:"is_read"`
	ActionURL string                 `json:"action_url,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// GroupComparisonReport represents comparison between groups
type GroupComparisonReport struct {
	Groups      []entities.Group   `json:"groups"`
	Comparison  []ComparisonItem   `json:"comparison"`
	Summary     *ComparisonSummary `json:"summary"`
	GeneratedAt string             `json:"generated_at"`
}

// ComparisonItem represents single comparison metric
type ComparisonItem struct {
	Metric string               `json:"metric"`
	Values map[uint]interface{} `json:"values"` // GroupID -> Value
}

// ComparisonSummary represents comparison summary
type ComparisonSummary struct {
	TotalGroups     int                `json:"total_groups"`
	LargestGroup    *GroupStats        `json:"largest_group"`
	SmallestGroup   *GroupStats        `json:"smallest_group"`
	MostActiveGroup *GroupStats        `json:"most_active_group"`
	Totals          map[string]int64   `json:"totals"`
	Averages        map[string]float64 `json:"averages"`
}

// GroupExportData represents data for group export
type GroupExportData struct {
	Group      *entities.Group    `json:"group"`
	Members    []GroupMemberInfo  `json:"members"`
	Servers    []GroupServerInfo  `json:"servers"`
	Projects   []GroupProjectInfo `json:"projects"`
	Stats      *GroupStats        `json:"stats"`
	Hierarchy  *GroupHierarchy    `json:"hierarchy"`
	ExportedAt string             `json:"exported_at"`
	ExportedBy string             `json:"exported_by"`
}

// GroupImportData represents data for group import
type GroupImportData struct {
	Groups      []entities.Group     `json:"groups"`
	Memberships []GroupMemberMapping `json:"memberships"`
	Hierarchy   []HierarchyMapping   `json:"hierarchy"`
	ImportMode  string               `json:"import_mode"` // create, update, merge
}

// GroupMemberMapping represents member mapping for import
type GroupMemberMapping struct {
	GroupName string   `json:"group_name"`
	Usernames []string `json:"usernames"`
	Role      string   `json:"role"`
}

// HierarchyMapping represents hierarchy mapping for import
type HierarchyMapping struct {
	ChildGroupName  string `json:"child_group_name"`
	ParentGroupName string `json:"parent_group_name"`
}
