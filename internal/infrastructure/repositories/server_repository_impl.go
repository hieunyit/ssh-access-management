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

type serverRepository struct {
	db *gorm.DB
}

// NewServerRepository creates a new server repository
func NewServerRepository(db *gorm.DB) repositories.ServerRepository {
	return &serverRepository{db: db}
}

// Create creates a new server
func (r *serverRepository) Create(ctx context.Context, server *entities.Server) error {
	if err := r.db.WithContext(ctx).Create(server).Error; err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return entities.ErrServerAlreadyExists
		}
		return fmt.Errorf("failed to create server: %w", err)
	}
	return nil
}

// GetByID retrieves a server by ID
func (r *serverRepository) GetByID(ctx context.Context, id uint) (*entities.Server, error) {
	var server entities.Server
	if err := r.db.WithContext(ctx).
		Preload("Groups").
		Preload("Projects").
		First(&server, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, entities.ErrServerNotFound
		}
		return nil, fmt.Errorf("failed to get server: %w", err)
	}
	return &server, nil
}

// GetByName retrieves a server by name
func (r *serverRepository) GetByName(ctx context.Context, name string) (*entities.Server, error) {
	var server entities.Server
	if err := r.db.WithContext(ctx).
		Preload("Groups").
		Preload("Projects").
		Where("name = ?", name).
		First(&server).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, entities.ErrServerNotFound
		}
		return nil, fmt.Errorf("failed to get server by name: %w", err)
	}
	return &server, nil
}

// GetByIP retrieves a server by IP address
func (r *serverRepository) GetByIP(ctx context.Context, ip string) (*entities.Server, error) {
	var server entities.Server
	if err := r.db.WithContext(ctx).
		Preload("Groups").
		Preload("Projects").
		Where("ip = ?", ip).
		First(&server).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, entities.ErrServerNotFound
		}
		return nil, fmt.Errorf("failed to get server by IP: %w", err)
	}
	return &server, nil
}

// Update updates a server
func (r *serverRepository) Update(ctx context.Context, server *entities.Server) error {
	if err := r.db.WithContext(ctx).Save(server).Error; err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return entities.ErrServerAlreadyExists
		}
		return fmt.Errorf("failed to update server: %w", err)
	}
	return nil
}

// Delete soft deletes a server
func (r *serverRepository) Delete(ctx context.Context, id uint) error {
	if err := r.db.WithContext(ctx).Delete(&entities.Server{}, id).Error; err != nil {
		return fmt.Errorf("failed to delete server: %w", err)
	}
	return nil
}

// List retrieves servers with filtering and pagination
func (r *serverRepository) List(ctx context.Context, filter repositories.ServerFilter) ([]entities.Server, *repositories.PaginationResult, error) {
	var servers []entities.Server
	var total int64

	query := r.db.WithContext(ctx).Model(&entities.Server{})

	// Apply filters
	query = r.applyServerFilters(query, filter)

	// Count total records
	if err := query.Count(&total).Error; err != nil {
		return nil, nil, fmt.Errorf("failed to count servers: %w", err)
	}

	// Apply pagination and sorting
	query = r.applyPaginationAndSorting(query, filter.Pagination, filter.SortBy, filter.SortOrder)

	// Preload associations
	query = query.Preload("Groups").Preload("Projects")

	if err := query.Find(&servers).Error; err != nil {
		return nil, nil, fmt.Errorf("failed to list servers: %w", err)
	}

	pagination := repositories.NewPaginationResult(filter.Pagination.Page, filter.Pagination.PageSize, total)
	return servers, pagination, nil
}

// Activate activates a server
func (r *serverRepository) Activate(ctx context.Context, id uint) error {
	if err := r.db.WithContext(ctx).
		Model(&entities.Server{}).
		Where("id = ?", id).
		Update("status", entities.ServerStatusActive).Error; err != nil {
		return fmt.Errorf("failed to activate server: %w", err)
	}
	return nil
}

// Deactivate deactivates a server
func (r *serverRepository) Deactivate(ctx context.Context, id uint) error {
	if err := r.db.WithContext(ctx).
		Model(&entities.Server{}).
		Where("id = ?", id).
		Update("status", entities.ServerStatusInactive).Error; err != nil {
		return fmt.Errorf("failed to deactivate server: %w", err)
	}
	return nil
}

// Ban bans a server
func (r *serverRepository) Ban(ctx context.Context, id uint) error {
	if err := r.db.WithContext(ctx).
		Model(&entities.Server{}).
		Where("id = ?", id).
		Update("status", entities.ServerStatusBanned).Error; err != nil {
		return fmt.Errorf("failed to ban server: %w", err)
	}
	return nil
}

// UpdateStatus updates server status
func (r *serverRepository) UpdateStatus(ctx context.Context, id uint, status entities.ServerStatus) error {
	if err := r.db.WithContext(ctx).
		Model(&entities.Server{}).
		Where("id = ?", id).
		Update("status", status).Error; err != nil {
		return fmt.Errorf("failed to update server status: %w", err)
	}
	return nil
}

// GetServerGroups retrieves groups for a server
func (r *serverRepository) GetServerGroups(ctx context.Context, serverID uint) ([]entities.Group, error) {
	var groups []entities.Group
	if err := r.db.WithContext(ctx).
		Joins("JOIN server_groups ON server_groups.group_id = groups.id").
		Where("server_groups.server_id = ?", serverID).
		Find(&groups).Error; err != nil {
		return nil, fmt.Errorf("failed to get server groups: %w", err)
	}
	return groups, nil
}

// GetServerProjects retrieves projects for a server
func (r *serverRepository) GetServerProjects(ctx context.Context, serverID uint) ([]entities.Project, error) {
	var projects []entities.Project
	if err := r.db.WithContext(ctx).
		Joins("JOIN server_projects ON server_projects.project_id = projects.id").
		Where("server_projects.server_id = ?", serverID).
		Find(&projects).Error; err != nil {
		return nil, fmt.Errorf("failed to get server projects: %w", err)
	}
	return projects, nil
}

// AddToGroup adds server to a group
func (r *serverRepository) AddToGroup(ctx context.Context, serverID, groupID uint) error {
	server := entities.Server{ID: serverID}
	group := entities.Group{ID: groupID}

	if err := r.db.WithContext(ctx).Model(&server).Association("Groups").Append(&group); err != nil {
		return fmt.Errorf("failed to add server to group: %w", err)
	}
	return nil
}

// RemoveFromGroup removes server from a group
func (r *serverRepository) RemoveFromGroup(ctx context.Context, serverID, groupID uint) error {
	server := entities.Server{ID: serverID}
	group := entities.Group{ID: groupID}

	if err := r.db.WithContext(ctx).Model(&server).Association("Groups").Delete(&group); err != nil {
		return fmt.Errorf("failed to remove server from group: %w", err)
	}
	return nil
}

// AddToProject adds server to a project
func (r *serverRepository) AddToProject(ctx context.Context, serverID, projectID uint) error {
	server := entities.Server{ID: serverID}
	project := entities.Project{ID: projectID}

	if err := r.db.WithContext(ctx).Model(&server).Association("Projects").Append(&project); err != nil {
		return fmt.Errorf("failed to add server to project: %w", err)
	}
	return nil
}

// RemoveFromProject removes server from a project
func (r *serverRepository) RemoveFromProject(ctx context.Context, serverID, projectID uint) error {
	server := entities.Server{ID: serverID}
	project := entities.Project{ID: projectID}

	if err := r.db.WithContext(ctx).Model(&server).Association("Projects").Delete(&project); err != nil {
		return fmt.Errorf("failed to remove server from project: %w", err)
	}
	return nil
}

// AddTag adds a tag to server
func (r *serverRepository) AddTag(ctx context.Context, serverID uint, tag string) error {
	var server entities.Server
	if err := r.db.WithContext(ctx).First(&server, serverID).Error; err != nil {
		return fmt.Errorf("failed to get server: %w", err)
	}

	server.AddTag(tag)

	if err := r.db.WithContext(ctx).Save(&server).Error; err != nil {
		return fmt.Errorf("failed to add tag: %w", err)
	}
	return nil
}

// RemoveTag removes a tag from server
func (r *serverRepository) RemoveTag(ctx context.Context, serverID uint, tag string) error {
	var server entities.Server
	if err := r.db.WithContext(ctx).First(&server, serverID).Error; err != nil {
		return fmt.Errorf("failed to get server: %w", err)
	}

	server.RemoveTag(tag)

	if err := r.db.WithContext(ctx).Save(&server).Error; err != nil {
		return fmt.Errorf("failed to remove tag: %w", err)
	}
	return nil
}

// AddTags adds multiple tags to server
func (r *serverRepository) AddTags(ctx context.Context, serverID uint, tags []string) error {
	var server entities.Server
	if err := r.db.WithContext(ctx).First(&server, serverID).Error; err != nil {
		return fmt.Errorf("failed to get server: %w", err)
	}

	for _, tag := range tags {
		server.AddTag(tag)
	}

	if err := r.db.WithContext(ctx).Save(&server).Error; err != nil {
		return fmt.Errorf("failed to add tags: %w", err)
	}
	return nil
}

// GetServersByTag retrieves servers by tag
func (r *serverRepository) GetServersByTag(ctx context.Context, tag string) ([]entities.Server, error) {
	var servers []entities.Server
	if err := r.db.WithContext(ctx).
		Where("tags ? ?", tag).
		Find(&servers).Error; err != nil {
		return nil, fmt.Errorf("failed to get servers by tag: %w", err)
	}
	return servers, nil
}

// GetAllTags retrieves all unique tags
func (r *serverRepository) GetAllTags(ctx context.Context) ([]string, error) {
	var tags []string

	// PostgreSQL query to extract all tags from JSONB array
	if err := r.db.WithContext(ctx).Raw(`
		SELECT DISTINCT jsonb_array_elements_text(tags) as tag 
		FROM servers 
		WHERE tags IS NOT NULL AND jsonb_array_length(tags) > 0
		ORDER BY tag
	`).Pluck("tag", &tags).Error; err != nil {
		return nil, fmt.Errorf("failed to get all tags: %w", err)
	}

	return tags, nil
}

// GetByEnvironment retrieves servers by environment
func (r *serverRepository) GetByEnvironment(ctx context.Context, environment string) ([]entities.Server, error) {
	var servers []entities.Server
	if err := r.db.WithContext(ctx).
		Where("environment = ?", environment).
		Find(&servers).Error; err != nil {
		return nil, fmt.Errorf("failed to get servers by environment: %w", err)
	}
	return servers, nil
}

// GetByPlatform retrieves servers by platform
func (r *serverRepository) GetByPlatform(ctx context.Context, platform entities.Platform) ([]entities.Server, error) {
	var servers []entities.Server
	if err := r.db.WithContext(ctx).
		Where("platform = ?", platform).
		Find(&servers).Error; err != nil {
		return nil, fmt.Errorf("failed to get servers by platform: %w", err)
	}
	return servers, nil
}

// GetByOS retrieves servers by OS
func (r *serverRepository) GetByOS(ctx context.Context, os string) ([]entities.Server, error) {
	var servers []entities.Server
	if err := r.db.WithContext(ctx).
		Where("os ILIKE ?", "%"+os+"%").
		Find(&servers).Error; err != nil {
		return nil, fmt.Errorf("failed to get servers by OS: %w", err)
	}
	return servers, nil
}

// GetByRegion retrieves servers by region
func (r *serverRepository) GetByRegion(ctx context.Context, region string) ([]entities.Server, error) {
	var servers []entities.Server
	if err := r.db.WithContext(ctx).
		Where("region = ?", region).
		Find(&servers).Error; err != nil {
		return nil, fmt.Errorf("failed to get servers by region: %w", err)
	}
	return servers, nil
}

// SearchServers searches servers by query
func (r *serverRepository) SearchServers(ctx context.Context, query string) ([]entities.Server, error) {
	var servers []entities.Server
	searchTerm := "%" + query + "%"

	if err := r.db.WithContext(ctx).
		Where("name ILIKE ? OR ip ILIKE ? OR hostname ILIKE ? OR description ILIKE ?",
			searchTerm, searchTerm, searchTerm, searchTerm).
		Find(&servers).Error; err != nil {
		return nil, fmt.Errorf("failed to search servers: %w", err)
	}
	return servers, nil
}

// GetServerAccess retrieves access grants for a server
func (r *serverRepository) GetServerAccess(ctx context.Context, serverID uint) ([]entities.AccessGrant, error) {
	var grants []entities.AccessGrant
	if err := r.db.WithContext(ctx).
		Preload("User").
		Preload("Group").
		Preload("Project").
		Where("server_id = ?", serverID).
		Find(&grants).Error; err != nil {
		return nil, fmt.Errorf("failed to get server access: %w", err)
	}
	return grants, nil
}

// GetActiveServerAccess retrieves active access grants for a server
func (r *serverRepository) GetActiveServerAccess(ctx context.Context, serverID uint) ([]entities.AccessGrant, error) {
	var grants []entities.AccessGrant
	if err := r.db.WithContext(ctx).
		Preload("User").
		Preload("Group").
		Preload("Project").
		Where("server_id = ? AND status = ? AND (expires_at IS NULL OR expires_at > ?)",
			serverID, entities.AccessStatusActive, time.Now()).
		Find(&grants).Error; err != nil {
		return nil, fmt.Errorf("failed to get active server access: %w", err)
	}
	return grants, nil
}

// CheckServerConnectivity checks server connectivity
func (r *serverRepository) CheckServerConnectivity(ctx context.Context, serverID uint) (*repositories.ServerConnectivity, error) {
	// Get server info
	server, err := r.GetByID(ctx, serverID)
	if err != nil {
		return nil, err
	}

	// TODO: Implement actual connectivity check
	// This would involve SSH connection test, ping test, etc.
	connectivity := &repositories.ServerConnectivity{
		IsReachable:    true, // Mock data
		ResponseTime:   15.5,
		LastChecked:    time.Now().Format(time.RFC3339),
		SSHPort:        true,
		DNSResolution:  true,
		NetworkLatency: 12.3,
	}

	return connectivity, nil
}

// UpdateConnectivityStatus updates server connectivity status
func (r *serverRepository) UpdateConnectivityStatus(ctx context.Context, serverID uint, status bool) error {
	// In a real implementation, this would update a connectivity status field
	// For now, we'll just update the updated_at timestamp
	if err := r.db.WithContext(ctx).
		Model(&entities.Server{}).
		Where("id = ?", serverID).
		Update("updated_at", time.Now()).Error; err != nil {
		return fmt.Errorf("failed to update connectivity status: %w", err)
	}
	return nil
}

// GetServerStats retrieves server statistics
func (r *serverRepository) GetServerStats(ctx context.Context, serverID uint) (*repositories.ServerStats, error) {
	stats := &repositories.ServerStats{}

	// Get basic server info
	var server entities.Server
	if err := r.db.WithContext(ctx).First(&server, serverID).Error; err != nil {
		return nil, fmt.Errorf("failed to get server: %w", err)
	}

	// Count total access grants
	if err := r.db.WithContext(ctx).
		Model(&entities.AccessGrant{}).
		Where("server_id = ?", serverID).
		Count(&stats.AccessGrantsCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count access grants: %w", err)
	}

	// Count active access grants
	if err := r.db.WithContext(ctx).
		Model(&entities.AccessGrant{}).
		Where("server_id = ? AND status = ? AND (expires_at IS NULL OR expires_at > ?)",
			serverID, entities.AccessStatusActive, time.Now()).
		Count(&stats.ActiveUsers).Error; err != nil {
		return nil, fmt.Errorf("failed to count active access: %w", err)
	}

	// Count total unique users with access
	if err := r.db.WithContext(ctx).
		Table("access_grants").
		Select("COUNT(DISTINCT user_id)").
		Where("server_id = ? AND user_id IS NOT NULL", serverID).
		Scan(&stats.TotalUsers).Error; err != nil {
		return nil, fmt.Errorf("failed to count total users: %w", err)
	}

	// Count groups
	if err := r.db.WithContext(ctx).
		Table("server_groups").
		Where("server_id = ?", serverID).
		Count(&stats.GroupsCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count groups: %w", err)
	}

	// Count projects
	if err := r.db.WithContext(ctx).
		Table("server_projects").
		Where("server_id = ?", serverID).
		Count(&stats.ProjectsCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count projects: %w", err)
	}

	// Set default connectivity status
	stats.ConnectivityStatus = true
	now := time.Now().Format(time.RFC3339)
	stats.LastConnectivityCheck = &now

	// Get recent activities from audit logs
	var activities []repositories.ServerActivity
	var auditLogs []entities.AuditLog
	if err := r.db.WithContext(ctx).
		Where("resource = ? AND resource_id = ?", entities.ResourceServer, serverID).
		Order("timestamp DESC").
		Limit(10).
		Find(&auditLogs).Error; err == nil {

		for _, log := range auditLogs {
			activity := repositories.ServerActivity{
				Timestamp: log.Timestamp.Format(time.RFC3339),
				Action:    string(log.Action),
			}
			if log.UserID != nil {
				activity.UserID = *log.UserID
			}
			activities = append(activities, activity)
		}
	}
	stats.RecentActivities = activities

	return stats, nil
}

// GetServersByStatus retrieves servers by status
func (r *serverRepository) GetServersByStatus(ctx context.Context, status entities.ServerStatus) ([]entities.Server, error) {
	var servers []entities.Server
	if err := r.db.WithContext(ctx).
		Where("status = ?", status).
		Find(&servers).Error; err != nil {
		return nil, fmt.Errorf("failed to get servers by status: %w", err)
	}
	return servers, nil
}

// GetServersCount retrieves total servers count
func (r *serverRepository) GetServersCount(ctx context.Context) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).
		Model(&entities.Server{}).
		Count(&count).Error; err != nil {
		return 0, fmt.Errorf("failed to count servers: %w", err)
	}
	return count, nil
}

// GetActiveServersCount retrieves active servers count
func (r *serverRepository) GetActiveServersCount(ctx context.Context) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).
		Model(&entities.Server{}).
		Where("status = ?", entities.ServerStatusActive).
		Count(&count).Error; err != nil {
		return 0, fmt.Errorf("failed to count active servers: %w", err)
	}
	return count, nil
}

// GetPlatformSummary retrieves platform summary statistics
func (r *serverRepository) GetPlatformSummary(ctx context.Context) ([]repositories.PlatformSummary, error) {
	var summaries []repositories.PlatformSummary

	rows, err := r.db.WithContext(ctx).Raw(`
		SELECT 
			platform,
			COUNT(*) as total,
			COUNT(CASE WHEN status = ? THEN 1 END) as active,
			COUNT(CASE WHEN status = ? THEN 1 END) as inactive,
			COUNT(CASE WHEN status = ? THEN 1 END) as banned
		FROM servers 
		GROUP BY platform
		ORDER BY platform
	`, entities.ServerStatusActive, entities.ServerStatusInactive, entities.ServerStatusBanned).Rows()

	if err != nil {
		return nil, fmt.Errorf("failed to get platform summary: %w", err)
	}
	defer rows.Close()

	var totalServers int64
	r.db.WithContext(ctx).Model(&entities.Server{}).Count(&totalServers)

	for rows.Next() {
		var summary repositories.PlatformSummary
		if err := rows.Scan(&summary.Platform, &summary.Total, &summary.Active,
			&summary.Inactive, &summary.Banned); err != nil {
			return nil, fmt.Errorf("failed to scan platform summary: %w", err)
		}

		if totalServers > 0 {
			summary.Percentage = float64(summary.Total) / float64(totalServers) * 100
		}

		summaries = append(summaries, summary)
	}

	return summaries, nil
}

// GetEnvironmentSummary retrieves environment summary statistics
func (r *serverRepository) GetEnvironmentSummary(ctx context.Context) ([]repositories.EnvironmentSummary, error) {
	var summaries []repositories.EnvironmentSummary

	rows, err := r.db.WithContext(ctx).Raw(`
		SELECT 
			environment,
			COUNT(*) as total,
			COUNT(CASE WHEN status = ? THEN 1 END) as active,
			COUNT(CASE WHEN status = ? THEN 1 END) as inactive,
			COUNT(CASE WHEN status = ? THEN 1 END) as banned
		FROM servers 
		GROUP BY environment
		ORDER BY environment
	`, entities.ServerStatusActive, entities.ServerStatusInactive, entities.ServerStatusBanned).Rows()

	if err != nil {
		return nil, fmt.Errorf("failed to get environment summary: %w", err)
	}
	defer rows.Close()

	var totalServers int64
	r.db.WithContext(ctx).Model(&entities.Server{}).Count(&totalServers)

	for rows.Next() {
		var summary repositories.EnvironmentSummary
		if err := rows.Scan(&summary.Environment, &summary.Total, &summary.Active,
			&summary.Inactive, &summary.Banned); err != nil {
			return nil, fmt.Errorf("failed to scan environment summary: %w", err)
		}

		if totalServers > 0 {
			summary.Percentage = float64(summary.Total) / float64(totalServers) * 100
		}

		summaries = append(summaries, summary)
	}

	return summaries, nil
}

// BulkCreate creates multiple servers
func (r *serverRepository) BulkCreate(ctx context.Context, servers []entities.Server) error {
	if err := r.db.WithContext(ctx).CreateInBatches(servers, 100).Error; err != nil {
		return fmt.Errorf("failed to bulk create servers: %w", err)
	}
	return nil
}

// BulkUpdate updates multiple servers
func (r *serverRepository) BulkUpdate(ctx context.Context, servers []entities.Server) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, server := range servers {
			if err := tx.Save(&server).Error; err != nil {
				return fmt.Errorf("failed to update server %d: %w", server.ID, err)
			}
		}
		return nil
	})
}

// BulkDelete deletes multiple servers
func (r *serverRepository) BulkDelete(ctx context.Context, ids []uint) error {
	if err := r.db.WithContext(ctx).Delete(&entities.Server{}, ids).Error; err != nil {
		return fmt.Errorf("failed to bulk delete servers: %w", err)
	}
	return nil
}

// BulkUpdateTags updates tags for multiple servers
func (r *serverRepository) BulkUpdateTags(ctx context.Context, serverIDs []uint, tags []string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, serverID := range serverIDs {
			var server entities.Server
			if err := tx.First(&server, serverID).Error; err != nil {
				continue // Skip if server not found
			}

			// Replace existing tags with new ones
			server.Tags = entities.StringArray(tags)

			if err := tx.Save(&server).Error; err != nil {
				return fmt.Errorf("failed to update tags for server %d: %w", serverID, err)
			}
		}
		return nil
	})
}

// BulkUpdateStatus updates status for multiple servers
func (r *serverRepository) BulkUpdateStatus(ctx context.Context, serverIDs []uint, status entities.ServerStatus) error {
	if err := r.db.WithContext(ctx).
		Model(&entities.Server{}).
		Where("id IN ?", serverIDs).
		Update("status", status).Error; err != nil {
		return fmt.Errorf("failed to bulk update server status: %w", err)
	}
	return nil
}

// Helper methods

func (r *serverRepository) applyServerFilters(query *gorm.DB, filter repositories.ServerFilter) *gorm.DB {
	if filter.Name != "" {
		query = query.Where("name ILIKE ?", "%"+filter.Name+"%")
	}
	if filter.IP != "" {
		query = query.Where("ip = ?", filter.IP)
	}
	if filter.Hostname != "" {
		query = query.Where("hostname ILIKE ?", "%"+filter.Hostname+"%")
	}
	if filter.Environment != "" {
		query = query.Where("environment = ?", filter.Environment)
	}
	if filter.Platform != "" {
		query = query.Where("platform = ?", filter.Platform)
	}
	if filter.OS != "" {
		query = query.Where("os ILIKE ?", "%"+filter.OS+"%")
	}
	if filter.Status != "" {
		query = query.Where("status = ?", filter.Status)
	}
	if filter.Tag != "" {
		query = query.Where("tags ? ?", filter.Tag)
	}
	if filter.Region != "" {
		query = query.Where("region = ?", filter.Region)
	}
	if filter.Search != "" {
		searchTerm := "%" + filter.Search + "%"
		query = query.Where("name ILIKE ? OR ip ILIKE ? OR hostname ILIKE ? OR description ILIKE ?",
			searchTerm, searchTerm, searchTerm, searchTerm)
	}
	if filter.GroupID != nil {
		query = query.Joins("JOIN server_groups ON server_groups.server_id = servers.id").
			Where("server_groups.group_id = ?", *filter.GroupID)
	}
	if filter.ProjectID != nil {
		query = query.Joins("JOIN server_projects ON server_projects.server_id = servers.id").
			Where("server_projects.project_id = ?", *filter.ProjectID)
	}
	if filter.IsActive != nil {
		if *filter.IsActive {
			query = query.Where("status = ?", entities.ServerStatusActive)
		} else {
			query = query.Where("status != ?", entities.ServerStatusActive)
		}
	}
	return query
}

func (r *serverRepository) applyPaginationAndSorting(query *gorm.DB, pagination repositories.PaginationParams, sortBy, sortOrder string) *gorm.DB {
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
