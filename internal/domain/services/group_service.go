package services

import (
	"context"
	"ssh-access-management/internal/domain/entities"
	"ssh-access-management/internal/domain/repositories"
)

// GroupService defines group service interface
type GroupService interface {
	// Group Management
	CreateGroup(ctx context.Context, req CreateGroupRequest) (*entities.Group, error)
	GetGroup(ctx context.Context, id uint) (*entities.Group, error)
	GetGroupByName(ctx context.Context, name string) (*entities.Group, error)
	UpdateGroup(ctx context.Context, id uint, req UpdateGroupRequest) (*entities.Group, error)
	DeleteGroup(ctx context.Context, id uint) error
	ListGroups(ctx context.Context, req ListGroupsRequest) (*ListGroupsResponse, error)

	// Group Status Management
	ActivateGroup(ctx context.Context, id uint) error
	DeactivateGroup(ctx context.Context, id uint) error
	UpdateGroupStatus(ctx context.Context, id uint, isActive bool) error

	// Group Hierarchy Management
	GetGroupChildren(ctx context.Context, parentID uint) ([]entities.Group, error)
	GetGroupParent(ctx context.Context, groupID uint) (*entities.Group, error)
	GetGroupAncestors(ctx context.Context, groupID uint) ([]entities.Group, error)
	GetGroupDescendants(ctx context.Context, groupID uint) ([]entities.Group, error)
	GetGroupTree(ctx context.Context, rootID *uint) (*GroupTreeResponse, error)
	GetGroupPath(ctx context.Context, groupID uint) (string, error)
	GetGroupLevel(ctx context.Context, groupID uint) (int, error)
	MoveGroup(ctx context.Context, groupID uint, newParentID *uint) error
	ValidateHierarchy(ctx context.Context, groupID, parentID uint) error

	// User Management
	AddUserToGroup(ctx context.Context, groupID, userID uint) error
	RemoveUserFromGroup(ctx context.Context, groupID, userID uint) error
	GetGroupUsers(ctx context.Context, groupID uint) ([]entities.User, error)
	GetUserGroups(ctx context.Context, userID uint) ([]entities.Group, error)
	IsUserInGroup(ctx context.Context, groupID, userID uint) (bool, error)
	GetAllGroupUsers(ctx context.Context, groupID uint) ([]entities.User, error) // Including child groups
	BulkAddUsersToGroup(ctx context.Context, req BulkAddUsersToGroupRequest) (*BulkOperationResult, error)
	BulkRemoveUsersFromGroup(ctx context.Context, req BulkRemoveUsersFromGroupRequest) (*BulkOperationResult, error)
	TransferUsers(ctx context.Context, req TransferUsersRequest) (*TransferResult, error)

	// Server Management
	AddServerToGroup(ctx context.Context, groupID, serverID uint) error
	RemoveServerFromGroup(ctx context.Context, groupID, serverID uint) error
	GetGroupServers(ctx context.Context, groupID uint) ([]entities.Server, error)
	GetServerGroups(ctx context.Context, serverID uint) ([]entities.Group, error)
	IsServerInGroup(ctx context.Context, groupID, serverID uint) (bool, error)
	GetAllGroupServers(ctx context.Context, groupID uint) ([]entities.Server, error) // Including child groups
	BulkAddServersToGroup(ctx context.Context, req BulkAddServersToGroupRequest) (*BulkOperationResult, error)
	BulkRemoveServersFromGroup(ctx context.Context, req BulkRemoveServersFromGroupRequest) (*BulkOperationResult, error)

	// Project Management
	AddProjectToGroup(ctx context.Context, groupID, projectID uint) error
	RemoveProjectFromGroup(ctx context.Context, groupID, projectID uint) error
	GetGroupProjects(ctx context.Context, groupID uint) ([]entities.Project, error)
	GetProjectGroups(ctx context.Context, projectID uint) ([]entities.Group, error)
	IsProjectInGroup(ctx context.Context, groupID, projectID uint) (bool, error)
	BulkAddProjectsToGroup(ctx context.Context, req BulkAddProjectsToGroupRequest) (*BulkOperationResult, error)
	BulkRemoveProjectsFromGroup(ctx context.Context, req BulkRemoveProjectsFromGroupRequest) (*BulkOperationResult, error)

	// Group Filtering and Search
	GetGroupsByType(ctx context.Context, groupType entities.GroupType) ([]entities.Group, error)
	GetGroupsByParent(ctx context.Context, parentID *uint) ([]entities.Group, error)
	SearchGroups(ctx context.Context, req SearchGroupsRequest) (*SearchGroupsResponse, error)
	GetActiveGroups(ctx context.Context) ([]entities.Group, error)
	GetRootGroups(ctx context.Context) ([]entities.Group, error) // Groups without parent

	// Permission Management
	UpdateGroupPermissions(ctx context.Context, req UpdateGroupPermissionsRequest) (*entities.Group, error)
	GetGroupPermissions(ctx context.Context, groupID uint) (*entities.GroupPermissions, error)
	GetEffectiveGroupPermissions(ctx context.Context, groupID uint) (*entities.GroupPermissions, error) // Including inherited
	CanUserManageGroup(ctx context.Context, userID, groupID uint) (bool, error)
	GetUserAccessibleGroups(ctx context.Context, userID uint) ([]entities.Group, error)

	// Group Statistics and Analytics
	GetGroupStats(ctx context.Context, groupID uint) (*repositories.GroupStats, error)
	GetGroupActivity(ctx context.Context, req GroupActivityRequest) (*repositories.GroupActivity, error)
	GetGroupMembersActivity(ctx context.Context, req GroupMembersActivityRequest) ([]repositories.UserActivitySummary, error)
	GetGroupServerActivity(ctx context.Context, req GroupServerActivityRequest) ([]repositories.ServerActivitySummary, error)
	GetRecentGroupChanges(ctx context.Context, groupID uint, limit int) ([]repositories.GroupChange, error)
	GetGroupSummary(ctx context.Context) (*repositories.GroupSummary, error)
	GetGroupDashboard(ctx context.Context, req GroupDashboardRequest) (*repositories.GroupDashboard, error)

	// Bulk Operations
	BulkCreateGroups(ctx context.Context, req BulkCreateGroupsRequest) (*BulkCreateGroupsResult, error)
	BulkUpdateGroups(ctx context.Context, req BulkUpdateGroupsRequest) (*BulkUpdateGroupsResult, error)
	BulkDeleteGroups(ctx context.Context, req BulkDeleteGroupsRequest) (*BulkDeleteGroupsResult, error)
	BulkUpdateGroupStatus(ctx context.Context, req BulkUpdateGroupStatusRequest) (*BulkOperationResult, error)
	BulkUpdateGroupPermissions(ctx context.Context, req BulkUpdateGroupPermissionsRequest) (*BulkOperationResult, error)

	// Group Operations
	MergeGroups(ctx context.Context, req MergeGroupsRequest) (*MergeGroupsResult, error)
	SplitGroup(ctx context.Context, req SplitGroupRequest) (*SplitGroupResult, error)
	CloneGroup(ctx context.Context, req CloneGroupRequest) (*CloneGroupResult, error)
	ArchiveGroup(ctx context.Context, groupID uint, reason string) error
	RestoreGroup(ctx context.Context, groupID uint) error

	// Group Membership Analysis
	GetGroupMembership(ctx context.Context, req GroupMembershipRequest) (*GroupMembershipResponse, error)
	GetUserGroupMembership(ctx context.Context, userID uint) (*UserGroupMembershipResponse, error)
	GetGroupOverlap(ctx context.Context, req GroupOverlapRequest) (*GroupOverlapResponse, error)
	GetMembershipConflicts(ctx context.Context, groupID uint) (*MembershipConflictsResponse, error)

	// Cleanup Operations
	CleanupEmptyGroups(ctx context.Context, req CleanupEmptyGroupsRequest) (*CleanupResult, error)
	RemoveInactiveUsers(ctx context.Context, req RemoveInactiveUsersRequest) (*CleanupResult, error)
	ConsolidateGroups(ctx context.Context, req ConsolidateGroupsRequest) (*ConsolidationResult, error)

	// Import/Export
	ExportGroup(ctx context.Context, req ExportGroupRequest) (*ExportGroupResult, error)
	ImportGroups(ctx context.Context, req ImportGroupsRequest) (*ImportGroupsResult, error)
	ExportGroupHierarchy(ctx context.Context, req ExportGroupHierarchyRequest) (*ExportResult, error)
	ImportGroupHierarchy(ctx context.Context, req ImportGroupHierarchyRequest) (*ImportResult, error)

	// Group Templates
	CreateGroupTemplate(ctx context.Context, req CreateGroupTemplateRequest) (*GroupTemplate, error)
	GetGroupTemplate(ctx context.Context, templateID uint) (*GroupTemplate, error)
	ListGroupTemplates(ctx context.Context) ([]GroupTemplate, error)
	CreateGroupFromTemplate(ctx context.Context, req CreateGroupFromTemplateRequest) (*entities.Group, error)
	UpdateGroupTemplate(ctx context.Context, templateID uint, req UpdateGroupTemplateRequest) (*GroupTemplate, error)
	DeleteGroupTemplate(ctx context.Context, templateID uint) error

	// Compliance and Auditing
	ValidateGroupCompliance(ctx context.Context, groupID uint) (*GroupComplianceResult, error)
	GetGroupAccessReport(ctx context.Context, req GroupAccessReportRequest) (*GroupAccessReport, error)
	GetGroupMembersReport(ctx context.Context, req GroupMembersReportRequest) (*GroupMembersReport, error)
	GetGroupAuditLog(ctx context.Context, req GroupAuditLogRequest) (*GroupAuditLogResponse, error)
}

// Request/Response DTOs

type CreateGroupRequest struct {
	Name        string                    `json:"name" validate:"required,min=1,max=100"`
	Description string                    `json:"description,omitempty"`
	Type        entities.GroupType        `json:"type" validate:"required"`
	ParentID    *uint                     `json:"parent_id,omitempty"`
	Permissions entities.GroupPermissions `json:"permissions,omitempty"`
	UserIDs     []uint                    `json:"user_ids,omitempty"`
	ServerIDs   []uint                    `json:"server_ids,omitempty"`
	ProjectIDs  []uint                    `json:"project_ids,omitempty"`
	Tags        []string                  `json:"tags,omitempty"`
	Metadata    map[string]string         `json:"metadata,omitempty"`
}

type UpdateGroupRequest struct {
	Name        *string                    `json:"name,omitempty" validate:"omitempty,min=1,max=100"`
	Description *string                    `json:"description,omitempty"`
	Type        *entities.GroupType        `json:"type,omitempty"`
	ParentID    *uint                      `json:"parent_id,omitempty"`
	Permissions *entities.GroupPermissions `json:"permissions,omitempty"`
	IsActive    *bool                      `json:"is_active,omitempty"`
	Tags        []string                   `json:"tags,omitempty"`
	Metadata    map[string]string          `json:"metadata,omitempty"`
}

type ListGroupsRequest struct {
	Name         string   `json:"name,omitempty"`
	Type         string   `json:"type,omitempty"`
	ParentID     *uint    `json:"parent_id,omitempty"`
	IsActive     *bool    `json:"is_active,omitempty"`
	Search       string   `json:"search,omitempty"`
	HasUsers     *bool    `json:"has_users,omitempty"`
	HasServers   *bool    `json:"has_servers,omitempty"`
	HasProjects  *bool    `json:"has_projects,omitempty"`
	Level        *int     `json:"level,omitempty"`
	UserID       *uint    `json:"user_id,omitempty"`    // Filter groups containing this user
	ServerID     *uint    `json:"server_id,omitempty"`  // Filter groups containing this server
	ProjectID    *uint    `json:"project_id,omitempty"` // Filter groups containing this project
	Tags         []string `json:"tags,omitempty"`
	Page         int      `json:"page,omitempty"`
	PageSize     int      `json:"page_size,omitempty"`
	SortBy       string   `json:"sort_by,omitempty"`
	SortOrder    string   `json:"sort_order,omitempty"`
	IncludeStats bool     `json:"include_stats,omitempty"`
}

type ListGroupsResponse struct {
	Groups     []entities.Group               `json:"groups"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *repositories.GroupSummary     `json:"summary"`
	Filters    *AppliedGroupFilters           `json:"filters"`
}

type AppliedGroupFilters struct {
	Type        string `json:"type,omitempty"`
	ParentID    *uint  `json:"parent_id,omitempty"`
	IsActive    *bool  `json:"is_active,omitempty"`
	HasUsers    *bool  `json:"has_users,omitempty"`
	HasServers  *bool  `json:"has_servers,omitempty"`
	Search      string `json:"search,omitempty"`
	FilterCount int    `json:"filter_count"`
}

type GroupTreeResponse struct {
	Tree     []repositories.GroupHierarchy `json:"tree"`
	MaxDepth int                           `json:"max_depth"`
	Total    int64                         `json:"total"`
	Summary  *GroupTreeSummary             `json:"summary"`
}

type GroupTreeSummary struct {
	RootGroups   int64   `json:"root_groups"`
	LeafGroups   int64   `json:"leaf_groups"`
	AvgChildren  float64 `json:"avg_children"`
	MaxChildren  int     `json:"max_children"`
	TotalUsers   int64   `json:"total_users"`
	TotalServers int64   `json:"total_servers"`
}

type BulkAddUsersToGroupRequest struct {
	GroupID uint   `json:"group_id" validate:"required"`
	UserIDs []uint `json:"user_ids" validate:"required,min=1,max=100"`
}

type BulkRemoveUsersFromGroupRequest struct {
	GroupID uint   `json:"group_id" validate:"required"`
	UserIDs []uint `json:"user_ids" validate:"required,min=1,max=100"`
}

type BulkAddServersToGroupRequest struct {
	GroupID   uint   `json:"group_id" validate:"required"`
	ServerIDs []uint `json:"server_ids" validate:"required,min=1,max=100"`
}

type BulkRemoveServersFromGroupRequest struct {
	GroupID   uint   `json:"group_id" validate:"required"`
	ServerIDs []uint `json:"server_ids" validate:"required,min=1,max=100"`
}

type BulkAddProjectsToGroupRequest struct {
	GroupID    uint   `json:"group_id" validate:"required"`
	ProjectIDs []uint `json:"project_ids" validate:"required,min=1,max=50"`
}

type BulkRemoveProjectsFromGroupRequest struct {
	GroupID    uint   `json:"group_id" validate:"required"`
	ProjectIDs []uint `json:"project_ids" validate:"required,min=1,max=50"`
}

type TransferUsersRequest struct {
	FromGroupID  uint   `json:"from_group_id" validate:"required"`
	ToGroupID    uint   `json:"to_group_id" validate:"required"`
	UserIDs      []uint `json:"user_ids" validate:"required,min=1,max=100"`
	KeepInSource bool   `json:"keep_in_source,omitempty"` // Copy instead of move
}

type TransferResult struct {
	TotalRequested int                  `json:"total_requested"`
	Successful     int                  `json:"successful"`
	Failed         int                  `json:"failed"`
	Errors         []BulkOperationError `json:"errors,omitempty"`
	FromGroup      *entities.Group      `json:"from_group"`
	ToGroup        *entities.Group      `json:"to_group"`
}

type SearchGroupsRequest struct {
	Query      string   `json:"query" validate:"required,min=1"`
	SearchIn   []string `json:"search_in,omitempty"` // name, description, etc.
	Type       string   `json:"type,omitempty"`
	IsActive   *bool    `json:"is_active,omitempty"`
	MinUsers   *int     `json:"min_users,omitempty"`
	MaxUsers   *int     `json:"max_users,omitempty"`
	MinServers *int     `json:"min_servers,omitempty"`
	MaxServers *int     `json:"max_servers,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	Page       int      `json:"page,omitempty"`
	PageSize   int      `json:"page_size,omitempty"`
	SortBy     string   `json:"sort_by,omitempty"`
	SortOrder  string   `json:"sort_order,omitempty"`
}

type SearchGroupsResponse struct {
	Groups     []entities.Group               `json:"groups"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *SearchGroupsSummary           `json:"summary"`
	Query      string                         `json:"query"`
	Highlights map[uint][]string              `json:"highlights,omitempty"` // GroupID -> highlighted fields
}

type SearchGroupsSummary struct {
	TotalResults  int64            `json:"total_results"`
	ByType        map[string]int64 `json:"by_type"`
	ByLevel       map[int]int64    `json:"by_level"`
	MatchedFields []string         `json:"matched_fields"`
}

type UpdateGroupPermissionsRequest struct {
	GroupID         uint                      `json:"group_id" validate:"required"`
	Permissions     entities.GroupPermissions `json:"permissions" validate:"required"`
	ApplyToChildren bool                      `json:"apply_to_children,omitempty"`
}

type GroupActivityRequest struct {
	GroupID   uint                   `json:"group_id" validate:"required"`
	TimeRange repositories.TimeRange `json:"time_range"`
	Metrics   []string               `json:"metrics,omitempty"`
}

type GroupMembersActivityRequest struct {
	GroupID   uint                   `json:"group_id" validate:"required"`
	TimeRange repositories.TimeRange `json:"time_range"`
	Limit     int                    `json:"limit,omitempty"`
	SortBy    string                 `json:"sort_by,omitempty"`
}

type GroupServerActivityRequest struct {
	GroupID   uint                   `json:"group_id" validate:"required"`
	TimeRange repositories.TimeRange `json:"time_range"`
	Limit     int                    `json:"limit,omitempty"`
	SortBy    string                 `json:"sort_by,omitempty"`
}

type GroupDashboardRequest struct {
	GroupID     uint                   `json:"group_id" validate:"required"`
	Widgets     []string               `json:"widgets,omitempty"`
	TimeRange   repositories.TimeRange `json:"time_range,omitempty"`
	RefreshRate int                    `json:"refresh_rate,omitempty"` // seconds
}

type BulkCreateGroupsRequest struct {
	Groups []CreateGroupRequest `json:"groups" validate:"required,min=1,max=50"`
}

type BulkCreateGroupsResult struct {
	TotalRequested int                  `json:"total_requested"`
	Successful     int                  `json:"successful"`
	Failed         int                  `json:"failed"`
	CreatedGroups  []entities.Group     `json:"created_groups"`
	Errors         []BulkOperationError `json:"errors,omitempty"`
}

type BulkUpdateGroupsRequest struct {
	Updates []GroupUpdateItem `json:"updates" validate:"required,min=1,max=50"`
}

type GroupUpdateItem struct {
	ID   uint               `json:"id" validate:"required"`
	Data UpdateGroupRequest `json:"data"`
}

type BulkUpdateGroupsResult struct {
	TotalRequested int                  `json:"total_requested"`
	Successful     int                  `json:"successful"`
	Failed         int                  `json:"failed"`
	UpdatedGroups  []entities.Group     `json:"updated_groups"`
	Errors         []BulkOperationError `json:"errors,omitempty"`
}

type BulkDeleteGroupsRequest struct {
	GroupIDs []uint `json:"group_ids" validate:"required,min=1,max=50"`
	Force    bool   `json:"force,omitempty"`   // Delete even if has members
	Cascade  bool   `json:"cascade,omitempty"` // Delete child groups too
}

type BulkDeleteGroupsResult struct {
	TotalRequested int                  `json:"total_requested"`
	Successful     int                  `json:"successful"`
	Failed         int                  `json:"failed"`
	DeletedGroups  []uint               `json:"deleted_groups"`
	Errors         []BulkOperationError `json:"errors,omitempty"`
}

type BulkUpdateGroupStatusRequest struct {
	GroupIDs []uint `json:"group_ids" validate:"required,min=1,max=50"`
	IsActive bool   `json:"is_active"`
	Cascade  bool   `json:"cascade,omitempty"` // Apply to child groups too
}

type BulkUpdateGroupPermissionsRequest struct {
	GroupIDs    []uint                    `json:"group_ids" validate:"required,min=1,max=50"`
	Permissions entities.GroupPermissions `json:"permissions" validate:"required"`
	Merge       bool                      `json:"merge,omitempty"` // Merge with existing or replace
}

type MergeGroupsRequest struct {
	SourceGroupID uint   `json:"source_group_id" validate:"required"`
	TargetGroupID uint   `json:"target_group_id" validate:"required"`
	Strategy      string `json:"strategy" validate:"required,oneof=merge_all merge_users_only merge_servers_only"`
	DeleteSource  bool   `json:"delete_source,omitempty"`
}

type MergeGroupsResult struct {
	SourceGroup    *entities.Group `json:"source_group"`
	TargetGroup    *entities.Group `json:"target_group"`
	MergedUsers    int             `json:"merged_users"`
	MergedServers  int             `json:"merged_servers"`
	MergedProjects int             `json:"merged_projects"`
	Conflicts      []MergeConflict `json:"conflicts,omitempty"`
}

type MergeConflict struct {
	Type        string `json:"type"` // permission, metadata, etc.
	Description string `json:"description"`
	Resolution  string `json:"resolution"`
}

type SplitGroupRequest struct {
	GroupID         uint   `json:"group_id" validate:"required"`
	NewGroupName    string `json:"new_group_name" validate:"required"`
	UserIDs         []uint `json:"user_ids" validate:"required,min=1"`
	CopyServers     bool   `json:"copy_servers,omitempty"`
	CopyProjects    bool   `json:"copy_projects,omitempty"`
	CopyPermissions bool   `json:"copy_permissions,omitempty"`
}

type SplitGroupResult struct {
	OriginalGroup  *entities.Group `json:"original_group"`
	NewGroup       *entities.Group `json:"new_group"`
	MovedUsers     int             `json:"moved_users"`
	CopiedServers  int             `json:"copied_servers"`
	CopiedProjects int             `json:"copied_projects"`
}

type CloneGroupRequest struct {
	GroupID            uint   `json:"group_id" validate:"required"`
	NewGroupName       string `json:"new_group_name" validate:"required"`
	IncludeUsers       bool   `json:"include_users,omitempty"`
	IncludeServers     bool   `json:"include_servers,omitempty"`
	IncludeProjects    bool   `json:"include_projects,omitempty"`
	IncludePermissions bool   `json:"include_permissions,omitempty"`
	NewParentID        *uint  `json:"new_parent_id,omitempty"`
}

type CloneGroupResult struct {
	OriginalGroup  *entities.Group `json:"original_group"`
	ClonedGroup    *entities.Group `json:"cloned_group"`
	CopiedUsers    int             `json:"copied_users"`
	CopiedServers  int             `json:"copied_servers"`
	CopiedProjects int             `json:"copied_projects"`
}

type GroupMembershipRequest struct {
	GroupID          uint `json:"group_id" validate:"required"`
	IncludeInherited bool `json:"include_inherited,omitempty"`
	IncludeStats     bool `json:"include_stats,omitempty"`
	Page             int  `json:"page,omitempty"`
	PageSize         int  `json:"page_size,omitempty"`
}

type GroupMembershipResponse struct {
	Group      *entities.Group                `json:"group"`
	Members    []repositories.GroupMembership `json:"members"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *GroupMembershipSummary        `json:"summary"`
	Hierarchy  *repositories.GroupHierarchy   `json:"hierarchy,omitempty"`
}

type GroupMembershipSummary struct {
	TotalMembers     int64 `json:"total_members"`
	DirectMembers    int64 `json:"direct_members"`
	InheritedMembers int64 `json:"inherited_members"`
	ActiveMembers    int64 `json:"active_members"`
	InactiveMembers  int64 `json:"inactive_members"`
}

type UserGroupMembershipResponse struct {
	UserID          uint                           `json:"user_id"`
	Username        string                         `json:"username"`
	DirectGroups    []repositories.GroupMembership `json:"direct_groups"`
	InheritedGroups []repositories.GroupMembership `json:"inherited_groups"`
	AllGroups       []repositories.GroupMembership `json:"all_groups"`
	Summary         *UserGroupMembershipSummary    `json:"summary"`
}

type UserGroupMembershipSummary struct {
	TotalGroups     int64            `json:"total_groups"`
	DirectGroups    int64            `json:"direct_groups"`
	InheritedGroups int64            `json:"inherited_groups"`
	ByType          map[string]int64 `json:"by_type"`
	ByLevel         map[int]int64    `json:"by_level"`
}

type GroupOverlapRequest struct {
	GroupIDs []uint `json:"group_ids" validate:"required,min=2,max=10"`
	Type     string `json:"type" validate:"required,oneof=users servers projects"`
}

type GroupOverlapResponse struct {
	Groups  []entities.Group            `json:"groups"`
	Overlap []OverlapItem               `json:"overlap"`
	Summary *OverlapSummary             `json:"summary"`
	Matrix  map[string]map[string]int64 `json:"matrix"` // GroupID -> GroupID -> overlap count
}

type OverlapItem struct {
	ItemID   uint   `json:"item_id"`
	ItemName string `json:"item_name"`
	ItemType string `json:"item_type"`
	Groups   []uint `json:"groups"` // GroupIDs containing this item
}

type OverlapSummary struct {
	TotalItems       int64   `json:"total_items"`
	OverlappingItems int64   `json:"overlapping_items"`
	UniqueItems      int64   `json:"unique_items"`
	OverlapRate      float64 `json:"overlap_rate"`
	MaxOverlap       int     `json:"max_overlap"`
	AvgOverlap       float64 `json:"avg_overlap"`
}

type MembershipConflictsResponse struct {
	GroupID   uint                 `json:"group_id"`
	GroupName string               `json:"group_name"`
	Conflicts []MembershipConflict `json:"conflicts"`
	Summary   *ConflictsSummary    `json:"summary"`
}

type MembershipConflict struct {
	Type        string `json:"type"` // permission, role, access
	Description string `json:"description"`
	Severity    string `json:"severity"`
	AffectedIDs []uint `json:"affected_ids"`
	Resolution  string `json:"resolution,omitempty"`
}

type ConflictsSummary struct {
	TotalConflicts  int64            `json:"total_conflicts"`
	BySeverity      map[string]int64 `json:"by_severity"`
	ByType          map[string]int64 `json:"by_type"`
	ResolvableCount int64            `json:"resolvable_count"`
}

type CleanupEmptyGroupsRequest struct {
	ExcludeRootGroups bool     `json:"exclude_root_groups,omitempty"`
	ExcludeTypes      []string `json:"exclude_types,omitempty"`
	DryRun            bool     `json:"dry_run,omitempty"`
}

type RemoveInactiveUsersRequest struct {
	GroupID               uint `json:"group_id" validate:"required"`
	DaysSinceLastActivity int  `json:"days_since_last_activity" validate:"required,min=1"`
	DryRun                bool `json:"dry_run,omitempty"`
}

type ConsolidateGroupsRequest struct {
	SimilarityThreshold float64  `json:"similarity_threshold" validate:"required,min=0,max=1"`
	Types               []string `json:"types,omitempty"`
	DryRun              bool     `json:"dry_run,omitempty"`
	AutoMerge           bool     `json:"auto_merge,omitempty"`
}

type ConsolidationResult struct {
	CandidatePairs   []ConsolidationCandidate `json:"candidate_pairs"`
	AutoMerged       []MergeGroupsResult      `json:"auto_merged,omitempty"`
	TotalCandidates  int                      `json:"total_candidates"`
	MergedGroups     int                      `json:"merged_groups"`
	PotentialSavings int64                    `json:"potential_savings"`
	WasDryRun        bool                     `json:"was_dry_run"`
}

type ConsolidationCandidate struct {
	Group1ID         uint    `json:"group1_id"`
	Group1Name       string  `json:"group1_name"`
	Group2ID         uint    `json:"group2_id"`
	Group2Name       string  `json:"group2_name"`
	Similarity       float64 `json:"similarity"`
	CommonUsers      int64   `json:"common_users"`
	CommonServers    int64   `json:"common_servers"`
	MergeStrategy    string  `json:"merge_strategy"`
	EstimatedSavings int64   `json:"estimated_savings"`
}

type ExportGroupRequest struct {
	GroupID          uint   `json:"group_id" validate:"required"`
	Format           string `json:"format" validate:"required,oneof=json yaml excel csv"`
	IncludeMembers   bool   `json:"include_members,omitempty"`
	IncludeServers   bool   `json:"include_servers,omitempty"`
	IncludeProjects  bool   `json:"include_projects,omitempty"`
	IncludeStats     bool   `json:"include_stats,omitempty"`
	IncludeHierarchy bool   `json:"include_hierarchy,omitempty"`
}

type ExportGroupResult struct {
	Data       []byte                        `json:"data"`
	FileName   string                        `json:"file_name"`
	Format     string                        `json:"format"`
	Size       int64                         `json:"size"`
	GroupData  *repositories.GroupExportData `json:"group_data,omitempty"`
	ExportedAt string                        `json:"exported_at"`
}

type ImportGroupsRequest struct {
	Data       []byte                        `json:"data" validate:"required"`
	Format     string                        `json:"format" validate:"required,oneof=json yaml excel csv"`
	ImportMode string                        `json:"import_mode" validate:"required,oneof=create update upsert"`
	Mapping    *repositories.GroupImportData `json:"mapping,omitempty"`
	DryRun     bool                          `json:"dry_run,omitempty"`
	Validation bool                          `json:"validation,omitempty"`
}

type ImportGroupsResult struct {
	TotalGroups        int              `json:"total_groups"`
	CreatedGroups      int              `json:"created_groups"`
	UpdatedGroups      int              `json:"updated_groups"`
	SkippedGroups      int              `json:"skipped_groups"`
	FailedGroups       int              `json:"failed_groups"`
	CreatedMemberships int              `json:"created_memberships"`
	Errors             []ImportError    `json:"errors,omitempty"`
	Warnings           []ImportWarning  `json:"warnings,omitempty"`
	WasDryRun          bool             `json:"was_dry_run"`
	ImportedGroups     []entities.Group `json:"imported_groups,omitempty"`
}

type ExportGroupHierarchyRequest struct {
	RootGroupID  *uint  `json:"root_group_id,omitempty"` // If nil, export all
	Format       string `json:"format" validate:"required,oneof=json yaml tree dot"`
	MaxDepth     *int   `json:"max_depth,omitempty"`
	IncludeStats bool   `json:"include_stats,omitempty"`
}

type ImportGroupHierarchyRequest struct {
	Data           []byte `json:"data" validate:"required"`
	Format         string `json:"format" validate:"required,oneof=json yaml"`
	PreserveIDs    bool   `json:"preserve_ids,omitempty"`
	CreateMissing  bool   `json:"create_missing,omitempty"`
	UpdateExisting bool   `json:"update_existing,omitempty"`
	DryRun         bool   `json:"dry_run,omitempty"`
}

type GroupTemplate struct {
	ID             uint                      `json:"id"`
	Name           string                    `json:"name"`
	Description    string                    `json:"description"`
	Type           entities.GroupType        `json:"type"`
	Permissions    entities.GroupPermissions `json:"permissions"`
	DefaultUsers   []string                  `json:"default_users,omitempty"`   // Username patterns
	DefaultServers []string                  `json:"default_servers,omitempty"` // Server name patterns
	Metadata       map[string]string         `json:"metadata,omitempty"`
	IsPublic       bool                      `json:"is_public"`
	UsageCount     int64                     `json:"usage_count"`
	CreatedBy      uint                      `json:"created_by"`
	CreatedAt      string                    `json:"created_at"`
	UpdatedAt      string                    `json:"updated_at"`
}

type CreateGroupTemplateRequest struct {
	Name           string                    `json:"name" validate:"required"`
	Description    string                    `json:"description,omitempty"`
	Type           entities.GroupType        `json:"type" validate:"required"`
	Permissions    entities.GroupPermissions `json:"permissions"`
	DefaultUsers   []string                  `json:"default_users,omitempty"`
	DefaultServers []string                  `json:"default_servers,omitempty"`
	Metadata       map[string]string         `json:"metadata,omitempty"`
	IsPublic       bool                      `json:"is_public,omitempty"`
}

type UpdateGroupTemplateRequest struct {
	Name           *string                    `json:"name,omitempty"`
	Description    *string                    `json:"description,omitempty"`
	Type           *entities.GroupType        `json:"type,omitempty"`
	Permissions    *entities.GroupPermissions `json:"permissions,omitempty"`
	DefaultUsers   []string                   `json:"default_users,omitempty"`
	DefaultServers []string                   `json:"default_servers,omitempty"`
	Metadata       map[string]string          `json:"metadata,omitempty"`
	IsPublic       *bool                      `json:"is_public,omitempty"`
}

type CreateGroupFromTemplateRequest struct {
	TemplateID  uint                   `json:"template_id" validate:"required"`
	Name        string                 `json:"name" validate:"required"`
	Description string                 `json:"description,omitempty"`
	ParentID    *uint                  `json:"parent_id,omitempty"`
	UserIDs     []uint                 `json:"user_ids,omitempty"`
	ServerIDs   []uint                 `json:"server_ids,omitempty"`
	ProjectIDs  []uint                 `json:"project_ids,omitempty"`
	Overrides   map[string]interface{} `json:"overrides,omitempty"`
}

type GroupComplianceResult struct {
	GroupID     uint              `json:"group_id"`
	GroupName   string            `json:"group_name"`
	IsCompliant bool              `json:"is_compliant"`
	Score       float64           `json:"score"`
	Issues      []ComplianceIssue `json:"issues"`
	Checks      []ComplianceCheck `json:"checks"`
	ValidatedAt string            `json:"validated_at"`
}

type ComplianceIssue struct {
	Type          string `json:"type"`
	Severity      string `json:"severity"`
	Description   string `json:"description"`
	Resolution    string `json:"resolution,omitempty"`
	AffectedCount int64  `json:"affected_count"`
}

type ComplianceCheck struct {
	Name        string `json:"name"`
	Passed      bool   `json:"passed"`
	Description string `json:"description"`
	Value       string `json:"value,omitempty"`
	Expected    string `json:"expected,omitempty"`
}

type GroupAccessReportRequest struct {
	GroupID          uint                   `json:"group_id" validate:"required"`
	TimeRange        repositories.TimeRange `json:"time_range"`
	Format           string                 `json:"format" validate:"required,oneof=json excel pdf"`
	IncludeDetails   bool                   `json:"include_details,omitempty"`
	IncludeInherited bool                   `json:"include_inherited,omitempty"`
}

type GroupAccessReport struct {
	Group        *entities.Group           `json:"group"`
	TimeRange    repositories.TimeRange    `json:"time_range"`
	Summary      *GroupAccessReportSummary `json:"summary"`
	UserAccess   []UserAccessReportItem    `json:"user_access"`
	ServerAccess []ServerAccessReportItem  `json:"server_access"`
	Timeline     []AccessTimelineItem      `json:"timeline"`
	GeneratedAt  string                    `json:"generated_at"`
}

type GroupAccessReportSummary struct {
	TotalUsers        int64 `json:"total_users"`
	UsersWithAccess   int64 `json:"users_with_access"`
	TotalServers      int64 `json:"total_servers"`
	AccessibleServers int64 `json:"accessible_servers"`
	TotalAccess       int64 `json:"total_access"`
	ActiveAccess      int64 `json:"active_access"`
	ExpiredAccess     int64 `json:"expired_access"`
}

type UserAccessReportItem struct {
	UserID      uint    `json:"user_id"`
	Username    string  `json:"username"`
	FullName    string  `json:"full_name"`
	AccessCount int64   `json:"access_count"`
	LastAccess  *string `json:"last_access,omitempty"`
	Status      string  `json:"status"`
}

type ServerAccessReportItem struct {
	ServerID    uint    `json:"server_id"`
	ServerName  string  `json:"server_name"`
	Environment string  `json:"environment"`
	UserCount   int64   `json:"user_count"`
	AccessCount int64   `json:"access_count"`
	LastAccess  *string `json:"last_access,omitempty"`
}

type AccessTimelineItem struct {
	Date          string `json:"date"`
	NewAccess     int64  `json:"new_access"`
	RevokedAccess int64  `json:"revoked_access"`
	ActiveAccess  int64  `json:"active_access"`
	Usage         int64  `json:"usage"`
}

type GroupMembersReportRequest struct {
	GroupID          uint   `json:"group_id" validate:"required"`
	Format           string `json:"format" validate:"required,oneof=json excel pdf"`
	IncludeStats     bool   `json:"include_stats,omitempty"`
	IncludeActivity  bool   `json:"include_activity,omitempty"`
	IncludeInherited bool   `json:"include_inherited,omitempty"`
}

type GroupMembersReport struct {
	Group       *entities.Group            `json:"group"`
	Summary     *GroupMembersReportSummary `json:"summary"`
	Members     []MemberReportItem         `json:"members"`
	Statistics  *MemberStatistics          `json:"statistics,omitempty"`
	GeneratedAt string                     `json:"generated_at"`
}

type GroupMembersReportSummary struct {
	TotalMembers     int64 `json:"total_members"`
	DirectMembers    int64 `json:"direct_members"`
	InheritedMembers int64 `json:"inherited_members"`
	ActiveMembers    int64 `json:"active_members"`
	InactiveMembers  int64 `json:"inactive_members"`
}

type MemberReportItem struct {
	UserID         uint    `json:"user_id"`
	Username       string  `json:"username"`
	FullName       string  `json:"full_name"`
	Department     string  `json:"department"`
	Role           string  `json:"role"`
	Status         string  `json:"status"`
	MembershipType string  `json:"membership_type"` // direct, inherited
	JoinedAt       string  `json:"joined_at"`
	LastActivity   *string `json:"last_activity,omitempty"`
	AccessCount    int64   `json:"access_count,omitempty"`
}

type MemberStatistics struct {
	ByDepartment         map[string]int64 `json:"by_department"`
	ByRole               map[string]int64 `json:"by_role"`
	ByStatus             map[string]int64 `json:"by_status"`
	ByMembershipType     map[string]int64 `json:"by_membership_type"`
	ActivityDistribution []ActivityBucket `json:"activity_distribution"`
}

type ActivityBucket struct {
	Range string `json:"range"`
	Count int64  `json:"count"`
}

type GroupAuditLogRequest struct {
	GroupID   uint                   `json:"group_id" validate:"required"`
	TimeRange repositories.TimeRange `json:"time_range"`
	Actions   []string               `json:"actions,omitempty"`
	UserID    *uint                  `json:"user_id,omitempty"`
	Page      int                    `json:"page,omitempty"`
	PageSize  int                    `json:"page_size,omitempty"`
}

type GroupAuditLogResponse struct {
	Group      *entities.Group                `json:"group"`
	Logs       []entities.AuditLog            `json:"logs"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *GroupAuditLogSummary          `json:"summary"`
}

type GroupAuditLogSummary struct {
	TotalLogs     int64            `json:"total_logs"`
	ByAction      map[string]int64 `json:"by_action"`
	ByUser        map[string]int64 `json:"by_user"`
	ByStatus      map[string]int64 `json:"by_status"`
	RecentChanges int64            `json:"recent_changes"`
}

// Shared types
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

type ImportResult struct {
	TotalRecords      int             `json:"total_records"`
	ProcessedRecords  int             `json:"processed_records"`
	SuccessfulRecords int             `json:"successful_records"`
	FailedRecords     int             `json:"failed_records"`
	SkippedRecords    int             `json:"skipped_records"`
	Errors            []ImportError   `json:"errors,omitempty"`
	Warnings          []ImportWarning `json:"warnings,omitempty"`
	WasDryRun         bool            `json:"was_dry_run"`
	Duration          int64           `json:"duration_ms"`
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
