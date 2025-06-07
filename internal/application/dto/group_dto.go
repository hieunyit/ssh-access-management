package dto

import (
	"ssh-access-management/internal/domain/entities"
	"ssh-access-management/internal/domain/repositories"
)

// CreateGroupRequest represents request to create group
type CreateGroupRequest struct {
	Name        string                    `json:"name" validate:"required,min=1,max=100"`
	Description string                    `json:"description,omitempty"`
	Type        entities.GroupType        `json:"type" validate:"required,oneof=department team project role"`
	ParentID    *uint                     `json:"parent_id,omitempty"`
	Permissions entities.GroupPermissions `json:"permissions,omitempty"`
	UserIDs     []uint                    `json:"user_ids,omitempty"`
	ServerIDs   []uint                    `json:"server_ids,omitempty"`
	ProjectIDs  []uint                    `json:"project_ids,omitempty"`
}

// UpdateGroupRequest represents request to update group
type UpdateGroupRequest struct {
	Name        *string                    `json:"name,omitempty" validate:"omitempty,min=1,max=100"`
	Description *string                    `json:"description,omitempty"`
	Type        *entities.GroupType        `json:"type,omitempty" validate:"omitempty,oneof=department team project role"`
	ParentID    *uint                      `json:"parent_id,omitempty"`
	Permissions *entities.GroupPermissions `json:"permissions,omitempty"`
	IsActive    *bool                      `json:"is_active,omitempty"`
}

// ListGroupsRequest represents request to list groups
type ListGroupsRequest struct {
	Name        string `json:"name,omitempty"`
	Type        string `json:"type,omitempty"`
	ParentID    *uint  `json:"parent_id,omitempty"`
	IsActive    *bool  `json:"is_active,omitempty"`
	Search      string `json:"search,omitempty"`
	HasUsers    *bool  `json:"has_users,omitempty"`
	HasServers  *bool  `json:"has_servers,omitempty"`
	HasProjects *bool  `json:"has_projects,omitempty"`
	Page        int    `json:"page,omitempty"`
	PageSize    int    `json:"page_size,omitempty"`
	SortBy      string `json:"sort_by,omitempty"`
	SortOrder   string `json:"sort_order,omitempty"`
}

// ListGroupsResponse represents response for listing groups
type ListGroupsResponse struct {
	Groups     []entities.Group               `json:"groups"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *GroupsSummary                 `json:"summary"`
}

// GroupDetailsResponse represents detailed group information
type GroupDetailsResponse struct {
	Group       *entities.Group    `json:"group"`
	Users       []GroupUserInfo    `json:"users"`
	Servers     []GroupServerInfo  `json:"servers"`
	Projects    []GroupProjectInfo `json:"projects"`
	Children    []entities.Group   `json:"children"`
	Parent      *entities.Group    `json:"parent,omitempty"`
	Stats       *GroupStats        `json:"stats"`
	Permissions []string           `json:"permissions"`
	Hierarchy   *GroupHierarchy    `json:"hierarchy,omitempty"`
}

// GroupUserInfo represents user information in group
type GroupUserInfo struct {
	UserID     uint   `json:"user_id"`
	Username   string `json:"username"`
	FullName   string `json:"full_name"`
	Email      string `json:"email"`
	Role       string `json:"role"`
	Status     string `json:"status"`
	Department string `json:"department"`
	JoinedAt   string `json:"joined_at"`
}

// GroupServerInfo represents server information in group
type GroupServerInfo struct {
	ServerID    uint   `json:"server_id"`
	Name        string `json:"name"`
	IP          string `json:"ip"`
	Hostname    string `json:"hostname"`
	Environment string `json:"environment"`
	Platform    string `json:"platform"`
	Status      string `json:"status"`
	AddedAt     string `json:"added_at"`
}

// GroupProjectInfo represents project information in group
type GroupProjectInfo struct {
	ProjectID   uint   `json:"project_id"`
	Name        string `json:"name"`
	Code        string `json:"code"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Priority    string `json:"priority"`
	AddedAt     string `json:"added_at"`
}

// GroupStats represents group statistics
type GroupStats struct {
	TotalUsers        int64            `json:"total_users"`
	ActiveUsers       int64            `json:"active_users"`
	TotalServers      int64            `json:"total_servers"`
	ActiveServers     int64            `json:"active_servers"`
	TotalProjects     int64            `json:"total_projects"`
	ActiveProjects    int64            `json:"active_projects"`
	DirectChildren    int64            `json:"direct_children"`
	TotalDescendants  int64            `json:"total_descendants"`
	UsersByRole       map[string]int64 `json:"users_by_role"`
	ServersByPlatform map[string]int64 `json:"servers_by_platform"`
	CreatedAt         string           `json:"created_at"`
	LastActivity      string           `json:"last_activity,omitempty"`
}

// GroupsSummary represents summary of groups
type GroupsSummary struct {
	Total        int64            `json:"total"`
	Active       int64            `json:"active"`
	Inactive     int64            `json:"inactive"`
	ByType       map[string]int64 `json:"by_type"`
	WithUsers    int64            `json:"with_users"`
	WithServers  int64            `json:"with_servers"`
	WithProjects int64            `json:"with_projects"`
}

// GroupHierarchy represents group hierarchy
type GroupHierarchy struct {
	ID          uint             `json:"id"`
	Name        string           `json:"name"`
	Type        string           `json:"type"`
	Level       int              `json:"level"`
	Path        string           `json:"path"`
	Children    []GroupHierarchy `json:"children,omitempty"`
	UserCount   int64            `json:"user_count"`
	ServerCount int64            `json:"server_count"`
}

// AddUsersToGroupRequest represents request to add users to group
type AddUsersToGroupRequest struct {
	UserIDs []uint `json:"user_ids" validate:"required,min=1,max=100"`
}

// RemoveUsersFromGroupRequest represents request to remove users from group
type RemoveUsersFromGroupRequest struct {
	UserIDs []uint `json:"user_ids" validate:"required,min=1,max=100"`
}

// AddServersToGroupRequest represents request to add servers to group
type AddServersToGroupRequest struct {
	ServerIDs []uint `json:"server_ids" validate:"required,min=1,max=100"`
}

// RemoveServersFromGroupRequest represents request to remove servers from group
type RemoveServersFromGroupRequest struct {
	ServerIDs []uint `json:"server_ids" validate:"required,min=1,max=100"`
}

// AddProjectsToGroupRequest represents request to add projects to group
type AddProjectsToGroupRequest struct {
	ProjectIDs []uint `json:"project_ids" validate:"required,min=1,max=100"`
}

// RemoveProjectsFromGroupRequest represents request to remove projects from group
type RemoveProjectsFromGroupRequest struct {
	ProjectIDs []uint `json:"project_ids" validate:"required,min=1,max=100"`
}

// GroupSearchFilters represents group search filters
type GroupSearchFilters struct {
	Type        string `json:"type,omitempty"`
	IsActive    *bool  `json:"is_active,omitempty"`
	HasParent   *bool  `json:"has_parent,omitempty"`
	HasChildren *bool  `json:"has_children,omitempty"`
	Level       *int   `json:"level,omitempty"`
	MinUsers    *int   `json:"min_users,omitempty"`
	MaxUsers    *int   `json:"max_users,omitempty"`
	MinServers  *int   `json:"min_servers,omitempty"`
	MaxServers  *int   `json:"max_servers,omitempty"`
}

// BulkCreateGroupsRequest represents bulk group creation request
type BulkCreateGroupsRequest struct {
	Groups []CreateGroupRequest `json:"groups" validate:"required,min=1,max=50"`
}

// BulkUpdateGroupsRequest represents bulk group update request
type BulkUpdateGroupsRequest struct {
	Updates []GroupUpdateItem `json:"updates" validate:"required,min=1,max=50"`
}

// GroupUpdateItem represents single group update in bulk operation
type GroupUpdateItem struct {
	ID   uint               `json:"id" validate:"required"`
	Data UpdateGroupRequest `json:"data"`
}

// GroupTreeResponse represents group tree structure
type GroupTreeResponse struct {
	Tree     []GroupHierarchy `json:"tree"`
	MaxDepth int              `json:"max_depth"`
	Total    int64            `json:"total"`
}

// GroupMembersResponse represents group members response
type GroupMembersResponse struct {
	Users      []GroupUserInfo                `json:"users"`
	Servers    []GroupServerInfo              `json:"servers"`
	Projects   []GroupProjectInfo             `json:"projects"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *GroupMembersSummary           `json:"summary"`
}

// GroupMembersSummary represents summary of group members
type GroupMembersSummary struct {
	TotalUsers    int64            `json:"total_users"`
	TotalServers  int64            `json:"total_servers"`
	TotalProjects int64            `json:"total_projects"`
	UsersByRole   map[string]int64 `json:"users_by_role"`
	UsersByStatus map[string]int64 `json:"users_by_status"`
}

// GroupPermissionsRequest represents request to update group permissions
type GroupPermissionsRequest struct {
	Permissions entities.GroupPermissions `json:"permissions" validate:"required"`
}

// GroupActivity represents group activity information
type GroupActivity struct {
	GroupID       uint                   `json:"group_id"`
	GroupName     string                 `json:"group_name"`
	TimeRange     repositories.TimeRange `json:"time_range"`
	UserActivity  []UserActivitySummary  `json:"user_activity"`
	ServerAccess  []ServerAccessSummary  `json:"server_access"`
	RecentChanges []GroupChange          `json:"recent_changes"`
	Stats         *GroupActivityStats    `json:"stats"`
}

// UserActivitySummary represents user activity summary in group
type UserActivitySummary struct {
	UserID       uint   `json:"user_id"`
	Username     string `json:"username"`
	Actions      int64  `json:"actions"`
	ServerAccess int64  `json:"server_access"`
	LastActivity string `json:"last_activity"`
}

// ServerAccessSummary represents server access summary in group
type ServerAccessSummary struct {
	ServerID    uint   `json:"server_id"`
	ServerName  string `json:"server_name"`
	AccessCount int64  `json:"access_count"`
	UniqueUsers int64  `json:"unique_users"`
	LastAccess  string `json:"last_access"`
}

// GroupChange represents a change in group
type GroupChange struct {
	Type        string            `json:"type"`
	Action      string            `json:"action"`
	Description string            `json:"description"`
	UserID      *uint             `json:"user_id,omitempty"`
	Username    string            `json:"username,omitempty"`
	Timestamp   string            `json:"timestamp"`
	Details     map[string]string `json:"details,omitempty"`
}

// GroupActivityStats represents group activity statistics
type GroupActivityStats struct {
	TotalActions     int64 `json:"total_actions"`
	TotalConnections int64 `json:"total_connections"`
	ActiveUsers      int64 `json:"active_users"`
	ActiveServers    int64 `json:"active_servers"`
	NewMembers       int64 `json:"new_members"`
	RemovedMembers   int64 `json:"removed_members"`
}
