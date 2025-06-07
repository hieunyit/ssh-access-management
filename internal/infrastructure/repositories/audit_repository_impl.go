package repositories

import (
	"context"
	"fmt"
	"time"

	"ssh-access-management/internal/domain/entities"
	"ssh-access-management/internal/domain/repositories"

	"gorm.io/gorm"
)

type auditRepository struct {
	db *gorm.DB
}

// NewAuditRepository creates a new audit repository
func NewAuditRepository(db *gorm.DB) repositories.AuditRepository {
	return &auditRepository{db: db}
}

// Create creates a new audit log entry
func (r *auditRepository) Create(ctx context.Context, log *entities.AuditLog) error {
	if err := r.db.WithContext(ctx).Create(log).Error; err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}
	return nil
}

// GetByID retrieves an audit log by ID
func (r *auditRepository) GetByID(ctx context.Context, id uint) (*entities.AuditLog, error) {
	var log entities.AuditLog
	if err := r.db.WithContext(ctx).
		Preload("User").
		First(&log, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("audit log not found")
		}
		return nil, fmt.Errorf("failed to get audit log: %w", err)
	}
	return &log, nil
}

// List retrieves audit logs with filtering and pagination
func (r *auditRepository) List(ctx context.Context, filter repositories.AuditFilter) ([]entities.AuditLog, *repositories.PaginationResult, error) {
	var logs []entities.AuditLog
	var total int64

	query := r.db.WithContext(ctx).Model(&entities.AuditLog{})

	// Apply filters
	query = r.applyAuditFilters(query, filter)

	// Count total records
	if err := query.Count(&total).Error; err != nil {
		return nil, nil, fmt.Errorf("failed to count audit logs: %w", err)
	}

	// Apply pagination and sorting
	query = r.applyPaginationAndSorting(query, filter.Pagination, filter.SortBy, filter.SortOrder)

	// Preload associations
	query = query.Preload("User")

	if err := query.Find(&logs).Error; err != nil {
		return nil, nil, fmt.Errorf("failed to list audit logs: %w", err)
	}

	pagination := repositories.NewPaginationResult(filter.Pagination.Page, filter.Pagination.PageSize, total)
	return logs, pagination, nil
}

// Delete deletes an audit log by ID
func (r *auditRepository) Delete(ctx context.Context, id uint) error {
	if err := r.db.WithContext(ctx).Delete(&entities.AuditLog{}, id).Error; err != nil {
		return fmt.Errorf("failed to delete audit log: %w", err)
	}
	return nil
}

// LogUserAction logs a user action
func (r *auditRepository) LogUserAction(ctx context.Context, userID *uint, action entities.AuditAction, details entities.AuditDetails, ip, userAgent string) error {
	log := entities.CreateAuditLog(action, entities.ResourceUser, userID)
	log.IPAddress = ip
	log.UserAgent = userAgent
	log.Details = details

	return r.Create(ctx, log)
}

// LogServerAction logs a server action
func (r *auditRepository) LogServerAction(ctx context.Context, userID *uint, serverID uint, action entities.AuditAction, details entities.AuditDetails, ip string) error {
	log := entities.CreateAuditLog(action, entities.ResourceServer, userID)
	log.ResourceID = &serverID
	log.IPAddress = ip
	log.Details = details

	return r.Create(ctx, log)
}

// LogAccessAction logs an access action
func (r *auditRepository) LogAccessAction(ctx context.Context, userID *uint, action entities.AuditAction, resourceID uint, details entities.AuditDetails, ip string) error {
	log := entities.CreateAuditLog(action, entities.ResourceAccess, userID)
	log.ResourceID = &resourceID
	log.IPAddress = ip
	log.Details = details

	return r.Create(ctx, log)
}

// LogSystemAction logs a system action
func (r *auditRepository) LogSystemAction(ctx context.Context, action entities.AuditAction, details entities.AuditDetails) error {
	log := entities.CreateAuditLog(action, entities.ResourceSystem, nil)
	log.Details = details

	return r.Create(ctx, log)
}

// LogAPIRequest logs an API request
func (r *auditRepository) LogAPIRequest(ctx context.Context, userID *uint, method, endpoint, ip, userAgent string, duration int64, status entities.AuditStatus) error {
	log := entities.CreateAPIAuditLog(method, endpoint, userID, ip, userAgent)
	log.Duration = duration
	log.Status = status

	return r.Create(ctx, log)
}

// SSH activity logging methods

func (r *auditRepository) LogSSHConnection(ctx context.Context, userID, serverID uint, ip, sessionID string, success bool) error {
	action := entities.ActionSSHConnect
	status := entities.StatusSuccess
	if !success {
		status = entities.StatusFailure
	}

	log := entities.CreateSSHAuditLog(action, &userID, serverID, ip)
	log.SessionID = sessionID
	log.Status = status

	return r.Create(ctx, log)
}

func (r *auditRepository) LogSSHDisconnection(ctx context.Context, userID, serverID uint, sessionID string, duration int64) error {
	log := entities.CreateSSHAuditLog(entities.ActionSSHDisconnect, &userID, serverID, "")
	log.SessionID = sessionID
	log.Duration = duration

	return r.Create(ctx, log)
}

func (r *auditRepository) LogSSHCommand(ctx context.Context, userID, serverID uint, sessionID, command string, exitCode int, duration int64) error {
	log := entities.CreateSSHAuditLog(entities.ActionSSHCommand, &userID, serverID, "")
	log.SessionID = sessionID
	log.Duration = duration
	log.SetCommand(command, exitCode)

	return r.Create(ctx, log)
}

func (r *auditRepository) LogSSHFileTransfer(ctx context.Context, userID, serverID uint, sessionID, filePath string, fileSize int64, direction string) error {
	log := entities.CreateSSHAuditLog(entities.ActionSSHFileTransfer, &userID, serverID, "")
	log.SessionID = sessionID
	log.SetFileTransfer(filePath, fileSize)
	log.Details.Description = fmt.Sprintf("File transfer (%s): %s", direction, filePath)

	return r.Create(ctx, log)
}

func (r *auditRepository) LogSSHPortForward(ctx context.Context, userID, serverID uint, sessionID string, localPort, remotePort int, remoteHost string) error {
	log := entities.CreateSSHAuditLog(entities.ActionSSHPortForward, &userID, serverID, "")
	log.SessionID = sessionID
	log.SetPortForward(localPort, remotePort, remoteHost)

	return r.Create(ctx, log)
}

// Security event logging methods

func (r *auditRepository) LogSecurityEvent(ctx context.Context, userID *uint, event string, severity entities.AuditSeverity, details entities.AuditDetails, ip, userAgent string) error {
	log := entities.CreateSecurityAuditLog(entities.AuditAction(event), userID, ip, userAgent)
	log.Severity = severity
	log.Details = details

	return r.Create(ctx, log)
}

func (r *auditRepository) LogFailedLogin(ctx context.Context, username, ip, userAgent string, reason string) error {
	log := entities.CreateSecurityAuditLog(entities.ActionUserLogin, nil, ip, userAgent)
	log.Status = entities.StatusFailure
	log.Details.Description = fmt.Sprintf("Failed login attempt for user: %s. Reason: %s", username, reason)
	log.Details.ErrorMessage = reason

	return r.Create(ctx, log)
}

func (r *auditRepository) LogSuccessfulLogin(ctx context.Context, userID uint, ip, userAgent string) error {
	log := entities.CreateSecurityAuditLog(entities.ActionUserLogin, &userID, ip, userAgent)
	log.Status = entities.StatusSuccess
	log.Details.Description = "Successful user login"

	return r.Create(ctx, log)
}

func (r *auditRepository) LogPasswordChange(ctx context.Context, userID uint, ip, userAgent string, forced bool) error {
	log := entities.CreateSecurityAuditLog(entities.ActionUserPasswordChange, &userID, ip, userAgent)
	if forced {
		log.Details.Description = "Password reset by administrator"
	} else {
		log.Details.Description = "Password changed by user"
	}

	return r.Create(ctx, log)
}

func (r *auditRepository) LogAccountLockout(ctx context.Context, userID uint, ip, reason string) error {
	log := entities.CreateSecurityAuditLog(entities.ActionUserLockout, &userID, ip, "")
	log.Details.Description = fmt.Sprintf("Account locked. Reason: %s", reason)
	log.Severity = entities.SeverityHigh

	return r.Create(ctx, log)
}

// Filtering and search methods

func (r *auditRepository) GetByUser(ctx context.Context, userID uint, filter repositories.AuditFilter) ([]entities.AuditLog, *repositories.PaginationResult, error) {
	filter.UserID = &userID
	return r.List(ctx, filter)
}

func (r *auditRepository) GetByServer(ctx context.Context, serverID uint, filter repositories.AuditFilter) ([]entities.AuditLog, *repositories.PaginationResult, error) {
	filter.ResourceID = &serverID
	filter.Resource = string(entities.ResourceServer)
	return r.List(ctx, filter)
}

func (r *auditRepository) GetByAction(ctx context.Context, action entities.AuditAction, filter repositories.AuditFilter) ([]entities.AuditLog, *repositories.PaginationResult, error) {
	filter.Action = string(action)
	return r.List(ctx, filter)
}

func (r *auditRepository) GetByResource(ctx context.Context, resource entities.AuditResource, filter repositories.AuditFilter) ([]entities.AuditLog, *repositories.PaginationResult, error) {
	filter.Resource = string(resource)
	return r.List(ctx, filter)
}

func (r *auditRepository) GetByDateRange(ctx context.Context, start, end time.Time, filter repositories.AuditFilter) ([]entities.AuditLog, *repositories.PaginationResult, error) {
	filter.StartTime = &start
	filter.EndTime = &end
	return r.List(ctx, filter)
}

func (r *auditRepository) GetSecurityEvents(ctx context.Context, filter repositories.AuditFilter) ([]entities.AuditLog, *repositories.PaginationResult, error) {
	securityEvent := true
	filter.IsSecurityEvent = &securityEvent
	return r.List(ctx, filter)
}

func (r *auditRepository) GetFailedEvents(ctx context.Context, filter repositories.AuditFilter) ([]entities.AuditLog, *repositories.PaginationResult, error) {
	filter.Status = string(entities.StatusFailure)
	return r.List(ctx, filter)
}

func (r *auditRepository) GetHighSeverityEvents(ctx context.Context, filter repositories.AuditFilter) ([]entities.AuditLog, *repositories.PaginationResult, error) {
	// Get high and critical severity events
	var logs []entities.AuditLog
	var total int64

	query := r.db.WithContext(ctx).Model(&entities.AuditLog{})
	query = query.Where("severity IN ?", []string{string(entities.SeverityHigh), string(entities.SeverityCritical)})

	// Apply other filters
	query = r.applyAuditFilters(query, filter)

	if err := query.Count(&total).Error; err != nil {
		return nil, nil, fmt.Errorf("failed to count high severity events: %w", err)
	}

	query = r.applyPaginationAndSorting(query, filter.Pagination, filter.SortBy, filter.SortOrder)
	query = query.Preload("User")

	if err := query.Find(&logs).Error; err != nil {
		return nil, nil, fmt.Errorf("failed to get high severity events: %w", err)
	}

	pagination := repositories.NewPaginationResult(filter.Pagination.Page, filter.Pagination.PageSize, total)
	return logs, pagination, nil
}

// Statistics and analytics methods

func (r *auditRepository) GetAuditStats(ctx context.Context, timeRange repositories.TimeRange) (*repositories.AuditStats, error) {
	stats := &repositories.AuditStats{
		TimeRange:      timeRange,
		LogsByAction:   make(map[string]int64),
		LogsByResource: make(map[string]int64),
		LogsByStatus:   make(map[string]int64),
		LogsBySeverity: make(map[string]int64),
	}

	// Total logs
	query := r.db.WithContext(ctx).Model(&entities.AuditLog{})
	if !timeRange.Start.IsZero() {
		query = query.Where("timestamp >= ?", timeRange.Start)
	}
	if !timeRange.End.IsZero() {
		query = query.Where("timestamp <= ?", timeRange.End)
	}

	query.Count(&stats.TotalLogs)

	// Security events
	query.Where("action IN ?", []string{
		string(entities.ActionUserLogin),
		string(entities.ActionUserLogout),
		string(entities.ActionSSHConnect),
		string(entities.ActionSSHCommand),
	}).Count(&stats.SecurityEvents)

	// Failed events
	query = r.db.WithContext(ctx).Model(&entities.AuditLog{})
	if !timeRange.Start.IsZero() {
		query = query.Where("timestamp >= ?", timeRange.Start)
	}
	if !timeRange.End.IsZero() {
		query = query.Where("timestamp <= ?", timeRange.End)
	}
	query.Where("status = ?", entities.StatusFailure).Count(&stats.FailedEvents)

	// Unique users, servers, IPs
	r.db.WithContext(ctx).Model(&entities.AuditLog{}).
		Where("timestamp BETWEEN ? AND ?", timeRange.Start, timeRange.End).
		Distinct("user_id").Count(&stats.UniqueUsers)

	r.db.WithContext(ctx).Model(&entities.AuditLog{}).
		Where("timestamp BETWEEN ? AND ? AND resource = ?", timeRange.Start, timeRange.End, entities.ResourceServer).
		Distinct("resource_id").Count(&stats.UniqueServers)

	r.db.WithContext(ctx).Model(&entities.AuditLog{}).
		Where("timestamp BETWEEN ? AND ?", timeRange.Start, timeRange.End).
		Distinct("ip_address").Count(&stats.UniqueIPs)

	// TODO: Calculate average response time and populate other fields

	return stats, nil
}

func (r *auditRepository) GetUserAuditStats(ctx context.Context, userID uint, timeRange repositories.TimeRange) (*repositories.UserAuditStats, error) {
	stats := &repositories.UserAuditStats{
		UserID:       userID,
		TimeRange:    timeRange,
		LogsByAction: make(map[string]int64),
		LogsByStatus: make(map[string]int64),
	}

	// Get user info
	var user entities.User
	if err := r.db.WithContext(ctx).First(&user, userID).Error; err == nil {
		stats.Username = user.Username
	}

	// Total logs for user
	query := r.db.WithContext(ctx).Model(&entities.AuditLog{}).Where("user_id = ?", userID)
	if !timeRange.Start.IsZero() {
		query = query.Where("timestamp >= ?", timeRange.Start)
	}
	if !timeRange.End.IsZero() {
		query = query.Where("timestamp <= ?", timeRange.End)
	}

	query.Count(&stats.TotalLogs)

	// Security events for user
	query.Where("action IN ?", []string{
		string(entities.ActionUserLogin),
		string(entities.ActionSSHConnect),
		string(entities.ActionSSHCommand),
	}).Count(&stats.SecurityEvents)

	// Failed events for user
	query = r.db.WithContext(ctx).Model(&entities.AuditLog{}).Where("user_id = ?", userID)
	if !timeRange.Start.IsZero() {
		query = query.Where("timestamp >= ?", timeRange.Start)
	}
	if !timeRange.End.IsZero() {
		query = query.Where("timestamp <= ?", timeRange.End)
	}
	query.Where("status = ?", entities.StatusFailure).Count(&stats.FailedEvents)

	// Servers accessed
	r.db.WithContext(ctx).Model(&entities.AuditLog{}).
		Where("user_id = ? AND resource = ? AND timestamp BETWEEN ? AND ?",
			userID, entities.ResourceServer, timeRange.Start, timeRange.End).
		Distinct("resource_id").Count(&stats.ServersAccessed)

	// Last activity
	var lastLog entities.AuditLog
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).
		Order("timestamp DESC").First(&lastLog).Error; err == nil {
		stats.LastActivity = &lastLog.Timestamp
	}

	// Recent activities
	var recentLogs []entities.AuditLog
	r.db.WithContext(ctx).Where("user_id = ?", userID).
		Order("timestamp DESC").Limit(10).Find(&recentLogs)
	stats.RecentActivities = recentLogs

	return stats, nil
}

func (r *auditRepository) GetServerAuditStats(ctx context.Context, serverID uint, timeRange repositories.TimeRange) (*repositories.ServerAuditStats, error) {
	stats := &repositories.ServerAuditStats{
		ServerID:     serverID,
		TimeRange:    timeRange,
		LogsByAction: make(map[string]int64),
		LogsByStatus: make(map[string]int64),
	}

	// Get server info
	var server entities.Server
	if err := r.db.WithContext(ctx).First(&server, serverID).Error; err == nil {
		stats.ServerName = server.Name
	}

	// Total logs for server
	query := r.db.WithContext(ctx).Model(&entities.AuditLog{}).
		Where("resource = ? AND resource_id = ?", entities.ResourceServer, serverID)
	if !timeRange.Start.IsZero() {
		query = query.Where("timestamp >= ?", timeRange.Start)
	}
	if !timeRange.End.IsZero() {
		query = query.Where("timestamp <= ?", timeRange.End)
	}

	query.Count(&stats.TotalLogs)

	// Security events for server
	query.Where("action IN ?", []string{
		string(entities.ActionSSHConnect),
		string(entities.ActionSSHCommand),
		string(entities.ActionServerAccess),
	}).Count(&stats.SecurityEvents)

	// Failed events for server
	query = r.db.WithContext(ctx).Model(&entities.AuditLog{}).
		Where("resource = ? AND resource_id = ?", entities.ResourceServer, serverID)
	if !timeRange.Start.IsZero() {
		query = query.Where("timestamp >= ?", timeRange.Start)
	}
	if !timeRange.End.IsZero() {
		query = query.Where("timestamp <= ?", timeRange.End)
	}
	query.Where("status = ?", entities.StatusFailure).Count(&stats.FailedEvents)

	// Unique users
	r.db.WithContext(ctx).Model(&entities.AuditLog{}).
		Where("resource = ? AND resource_id = ? AND timestamp BETWEEN ? AND ?",
			entities.ResourceServer, serverID, timeRange.Start, timeRange.End).
		Distinct("user_id").Count(&stats.UniqueUsers)

	// Last activity
	var lastLog entities.AuditLog
	if err := r.db.WithContext(ctx).
		Where("resource = ? AND resource_id = ?", entities.ResourceServer, serverID).
		Order("timestamp DESC").First(&lastLog).Error; err == nil {
		stats.LastActivity = &lastLog.Timestamp
	}

	// Recent activities
	var recentLogs []entities.AuditLog
	r.db.WithContext(ctx).
		Where("resource = ? AND resource_id = ?", entities.ResourceServer, serverID).
		Order("timestamp DESC").Limit(10).Find(&recentLogs)
	stats.RecentActivities = recentLogs

	return stats, nil
}

func (r *auditRepository) GetSecurityEventStats(ctx context.Context, timeRange repositories.TimeRange) (*repositories.SecurityEventStats, error) {
	stats := &repositories.SecurityEventStats{
		TimeRange:        timeRange,
		EventsBySeverity: make(map[string]int64),
		EventsByType:     make(map[string]int64),
	}

	query := r.db.WithContext(ctx).Model(&entities.AuditLog{})
	if !timeRange.Start.IsZero() {
		query = query.Where("timestamp >= ?", timeRange.Start)
	}
	if !timeRange.End.IsZero() {
		query = query.Where("timestamp <= ?", timeRange.End)
	}

	// Security actions
	securityActions := []string{
		string(entities.ActionUserLogin),
		string(entities.ActionUserLogout),
		string(entities.ActionUserPasswordChange),
		string(entities.ActionSSHConnect),
		string(entities.ActionSSHCommand),
	}

	query.Where("action IN ?", securityActions).Count(&stats.TotalEvents)

	// Failed logins
	query = r.db.WithContext(ctx).Model(&entities.AuditLog{})
	if !timeRange.Start.IsZero() {
		query = query.Where("timestamp >= ?", timeRange.Start)
	}
	if !timeRange.End.IsZero() {
		query = query.Where("timestamp <= ?", timeRange.End)
	}
	query.Where("action = ? AND status = ?", entities.ActionUserLogin, entities.StatusFailure).Count(&stats.FailedLogins)

	// Successful logins
	query = r.db.WithContext(ctx).Model(&entities.AuditLog{})
	if !timeRange.Start.IsZero() {
		query = query.Where("timestamp >= ?", timeRange.Start)
	}
	if !timeRange.End.IsZero() {
		query = query.Where("timestamp <= ?", timeRange.End)
	}
	query.Where("action = ? AND status = ?", entities.ActionUserLogin, entities.StatusSuccess).Count(&stats.SuccessfulLogins)

	// Password changes
	query = r.db.WithContext(ctx).Model(&entities.AuditLog{})
	if !timeRange.Start.IsZero() {
		query = query.Where("timestamp >= ?", timeRange.Start)
	}
	if !timeRange.End.IsZero() {
		query = query.Where("timestamp <= ?", timeRange.End)
	}
	query.Where("action = ?", entities.ActionUserPasswordChange).Count(&stats.PasswordChanges)

	// TODO: Populate other fields and get risk events

	return stats, nil
}

func (r *auditRepository) GetActivityTrends(ctx context.Context, timeRange repositories.TimeRange, granularity string) ([]repositories.ActivityTrend, error) {
	// Simplified implementation - would need complex time series queries
	var trends []repositories.ActivityTrend

	// For now, return empty trends
	return trends, nil
}

// Compliance and reporting methods (simplified implementations)

func (r *auditRepository) GetComplianceReport(ctx context.Context, start, end time.Time, filters repositories.ComplianceFilter) (*repositories.ComplianceReport, error) {
	report := &repositories.ComplianceReport{
		Standard:    filters.Standard,
		TimeRange:   repositories.NewTimeRangeFromDates(start, end),
		GeneratedAt: time.Now(),
	}

	// Count total events in time range
	r.db.WithContext(ctx).Model(&entities.AuditLog{}).
		Where("timestamp BETWEEN ? AND ?", start, end).
		Count(&report.TotalEvents)

	// TODO: Implement compliance scoring and violations
	report.ComplianceScore = 85.0

	return report, nil
}

func (r *auditRepository) GetAccessReport(ctx context.Context, start, end time.Time) (*repositories.AccessReport, error) {
	report := &repositories.AccessReport{
		TimeRange:           repositories.NewTimeRangeFromDates(start, end),
		GeneratedAt:         time.Now(),
		AccessByRole:        make(map[string]int64),
		AccessByEnvironment: make(map[string]int64),
	}

	// Count access events
	r.db.WithContext(ctx).Model(&entities.AuditLog{}).
		Where("timestamp BETWEEN ? AND ? AND action IN ?", start, end, []string{
			string(entities.ActionSSHConnect),
			string(entities.ActionServerAccess),
		}).Count(&report.TotalAccess)

	// Successful access
	r.db.WithContext(ctx).Model(&entities.AuditLog{}).
		Where("timestamp BETWEEN ? AND ? AND action IN ? AND status = ?", start, end, []string{
			string(entities.ActionSSHConnect),
			string(entities.ActionServerAccess),
		}, entities.StatusSuccess).Count(&report.SuccessfulAccess)

	// Failed access
	report.FailedAccess = report.TotalAccess - report.SuccessfulAccess

	// Unique users and servers
	r.db.WithContext(ctx).Model(&entities.AuditLog{}).
		Where("timestamp BETWEEN ? AND ?", start, end).
		Distinct("user_id").Count(&report.UniqueUsers)

	r.db.WithContext(ctx).Model(&entities.AuditLog{}).
		Where("timestamp BETWEEN ? AND ? AND resource = ?", start, end, entities.ResourceServer).
		Distinct("resource_id").Count(&report.UniqueServers)

	return report, nil
}

func (r *auditRepository) GetUserActivityReport(ctx context.Context, userID uint, start, end time.Time) (*repositories.UserActivityReport, error) {
	report := &repositories.UserActivityReport{
		UserID:      userID,
		TimeRange:   repositories.NewTimeRangeFromDates(start, end),
		GeneratedAt: time.Now(),
	}

	// Get user info
	var user entities.User
	if err := r.db.WithContext(ctx).First(&user, userID).Error; err == nil {
		report.Username = user.Username
		report.FullName = user.FullName
	}

	// Get activities
	r.db.WithContext(ctx).Where("user_id = ? AND timestamp BETWEEN ? AND ?", userID, start, end).
		Order("timestamp DESC").Find(&report.Activities)

	// Get user audit stats
	timeRange := repositories.NewTimeRangeFromDates(start, end)
	stats, err := r.GetUserAuditStats(ctx, userID, timeRange)
	if err == nil {
		report.Summary = *stats
	}

	// Get security events
	r.db.WithContext(ctx).Where("user_id = ? AND timestamp BETWEEN ? AND ? AND action IN ?",
		userID, start, end, []string{
			string(entities.ActionUserLogin),
			string(entities.ActionSSHConnect),
		}).Find(&report.SecurityEvents)

	return report, nil
}

func (r *auditRepository) GetServerActivityReport(ctx context.Context, serverID uint, start, end time.Time) (*repositories.ServerActivityReport, error) {
	report := &repositories.ServerActivityReport{
		ServerID:    serverID,
		TimeRange:   repositories.NewTimeRangeFromDates(start, end),
		GeneratedAt: time.Now(),
	}

	// Get server info
	var server entities.Server
	if err := r.db.WithContext(ctx).First(&server, serverID).Error; err == nil {
		report.ServerName = server.Name
		report.ServerIP = server.IP
	}

	// Get activities
	r.db.WithContext(ctx).
		Where("resource = ? AND resource_id = ? AND timestamp BETWEEN ? AND ?",
			entities.ResourceServer, serverID, start, end).
		Order("timestamp DESC").Find(&report.Activities)

	// Get server audit stats
	timeRange := repositories.NewTimeRangeFromDates(start, end)
	stats, err := r.GetServerAuditStats(ctx, serverID, timeRange)
	if err == nil {
		report.Summary = *stats
	}

	// Get security events
	r.db.WithContext(ctx).
		Where("resource = ? AND resource_id = ? AND timestamp BETWEEN ? AND ? AND action IN ?",
			entities.ResourceServer, serverID, start, end, []string{
				string(entities.ActionSSHConnect),
				string(entities.ActionSSHCommand),
			}).Find(&report.SecurityEvents)

	return report, nil
}

func (r *auditRepository) GetSecurityReport(ctx context.Context, start, end time.Time) (*repositories.SecurityReport, error) {
	report := &repositories.SecurityReport{
		TimeRange:   repositories.NewTimeRangeFromDates(start, end),
		GeneratedAt: time.Now(),
	}

	// Get security event stats
	timeRange := repositories.NewTimeRangeFromDates(start, end)
	stats, err := r.GetSecurityEventStats(ctx, timeRange)
	if err == nil {
		report.Summary = *stats
	}

	// TODO: Implement threat analysis, incidents, and recommendations

	return report, nil
}

// Data retention and cleanup methods

func (r *auditRepository) CleanupOldLogs(ctx context.Context, retentionDays int) (int64, error) {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	result := r.db.WithContext(ctx).Where("timestamp < ?", cutoff).Delete(&entities.AuditLog{})
	return result.RowsAffected, result.Error
}

func (r *auditRepository) ArchiveLogs(ctx context.Context, beforeDate time.Time) (int64, error) {
	// This would typically move logs to an archive table or external storage
	// For now, just count the logs that would be archived
	var count int64
	err := r.db.WithContext(ctx).Model(&entities.AuditLog{}).
		Where("timestamp < ?", beforeDate).Count(&count)
	return count, err
}

func (r *auditRepository) GetOldestLog(ctx context.Context) (*entities.AuditLog, error) {
	var log entities.AuditLog
	err := r.db.WithContext(ctx).Order("timestamp ASC").First(&log).Error
	if err != nil {
		return nil, err
	}
	return &log, nil
}

func (r *auditRepository) GetStorageStats(ctx context.Context) (*repositories.StorageStats, error) {
	stats := &repositories.StorageStats{}

	r.db.WithContext(ctx).Model(&entities.AuditLog{}).Count(&stats.TotalLogs)

	// Get oldest and newest logs
	var oldestLog, newestLog entities.AuditLog
	if err := r.db.WithContext(ctx).Order("timestamp ASC").First(&oldestLog).Error; err == nil {
		stats.OldestLog = oldestLog.Timestamp
	}
	if err := r.db.WithContext(ctx).Order("timestamp DESC").First(&newestLog).Error; err == nil {
		stats.NewestLog = newestLog.Timestamp
	}

	// TODO: Calculate actual storage size and other metrics
	stats.RetentionDays = 365 // Default retention

	return stats, nil
}

// Export and backup methods (simplified implementations)

func (r *auditRepository) ExportLogs(ctx context.Context, filter repositories.AuditFilter, format string) ([]byte, error) {
	// Get logs based on filter
	logs, _, err := r.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	// For now, return a simple JSON export
	// In production, would support CSV, Excel, etc.
	switch format {
	case "json":
		// Would implement JSON export
		return []byte("[]"), nil
	case "csv":
		// Would implement CSV export
		return []byte(""), nil
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

func (r *auditRepository) BackupLogs(ctx context.Context, start, end time.Time, location string) error {
	// Would implement backup to external storage
	return nil
}

// Real-time monitoring methods

func (r *auditRepository) GetRecentActivity(ctx context.Context, limit int) ([]entities.AuditLog, error) {
	var logs []entities.AuditLog
	err := r.db.WithContext(ctx).
		Preload("User").
		Order("timestamp DESC").
		Limit(limit).
		Find(&logs).Error
	return logs, err
}

func (r *auditRepository) GetLiveSecurityEvents(ctx context.Context, since time.Time) ([]entities.AuditLog, error) {
	var logs []entities.AuditLog
	err := r.db.WithContext(ctx).
		Preload("User").
		Where("timestamp > ? AND action IN ?", since, []string{
			string(entities.ActionUserLogin),
			string(entities.ActionSSHConnect),
			string(entities.ActionSSHCommand),
		}).
		Order("timestamp DESC").
		Find(&logs).Error
	return logs, err
}

func (r *auditRepository) GetAnomalousActivities(ctx context.Context, threshold float64) ([]entities.AuditLog, error) {
	// Simplified implementation - would use ML/statistics to detect anomalies
	var logs []entities.AuditLog
	err := r.db.WithContext(ctx).
		Where("severity IN ?", []string{string(entities.SeverityHigh), string(entities.SeverityCritical)}).
		Order("timestamp DESC").
		Limit(100).
		Find(&logs).Error
	return logs, err
}

// Bulk operations

func (r *auditRepository) BulkCreate(ctx context.Context, logs []entities.AuditLog) error {
	return r.db.WithContext(ctx).CreateInBatches(logs, 1000).Error
}

func (r *auditRepository) BulkDelete(ctx context.Context, ids []uint) error {
	return r.db.WithContext(ctx).Delete(&entities.AuditLog{}, ids).Error
}

// Helper methods

func (r *auditRepository) applyAuditFilters(query *gorm.DB, filter repositories.AuditFilter) *gorm.DB {
	if filter.UserID != nil {
		query = query.Where("user_id = ?", *filter.UserID)
	}
	if filter.Action != "" {
		query = query.Where("action = ?", filter.Action)
	}
	if filter.Resource != "" {
		query = query.Where("resource = ?", filter.Resource)
	}
	if filter.ResourceID != nil {
		query = query.Where("resource_id = ?", *filter.ResourceID)
	}
	if filter.Status != "" {
		query = query.Where("status = ?", filter.Status)
	}
	if filter.Severity != "" {
		query = query.Where("severity = ?", filter.Severity)
	}
	if filter.IPAddress != "" {
		query = query.Where("ip_address = ?", filter.IPAddress)
	}
	if filter.SessionID != "" {
		query = query.Where("session_id = ?", filter.SessionID)
	}
	if filter.RequestID != "" {
		query = query.Where("request_id = ?", filter.RequestID)
	}
	if filter.Method != "" {
		query = query.Where("method = ?", filter.Method)
	}
	if filter.Endpoint != "" {
		query = query.Where("endpoint ILIKE ?", "%"+filter.Endpoint+"%")
	}
	if filter.StartTime != nil {
		query = query.Where("timestamp >= ?", *filter.StartTime)
	}
	if filter.EndTime != nil {
		query = query.Where("timestamp <= ?", *filter.EndTime)
	}
	if filter.Search != "" {
		searchTerm := "%" + filter.Search + "%"
		query = query.Where("action ILIKE ? OR resource ILIKE ? OR endpoint ILIKE ?",
			searchTerm, searchTerm, searchTerm)
	}
	if len(filter.Tags) > 0 {
		query = query.Where("tags && ?", filter.Tags)
	}
	if filter.MinDuration != nil {
		query = query.Where("duration >= ?", *filter.MinDuration)
	}
	if filter.MaxDuration != nil {
		query = query.Where("duration <= ?", *filter.MaxDuration)
	}
	if filter.HasError != nil {
		if *filter.HasError {
			query = query.Where("status = ?", entities.StatusFailure)
		} else {
			query = query.Where("status != ?", entities.StatusFailure)
		}
	}
	if filter.IsSecurityEvent != nil && *filter.IsSecurityEvent {
		securityActions := []string{
			string(entities.ActionUserLogin),
			string(entities.ActionUserLogout),
			string(entities.ActionSSHConnect),
			string(entities.ActionSSHCommand),
		}
		query = query.Where("action IN ?", securityActions)
	}
	return query
}

func (r *auditRepository) applyPaginationAndSorting(query *gorm.DB, pagination repositories.PaginationParams, sortBy, sortOrder string) *gorm.DB {
	// Apply sorting
	if sortBy != "" {
		order := "ASC"
		if sortOrder == "desc" {
			order = "DESC"
		}
		query = query.Order(fmt.Sprintf("%s %s", sortBy, order))
	} else {
		query = query.Order("timestamp DESC")
	}

	// Apply pagination
	if pagination.Limit > 0 {
		query = query.Offset(pagination.Offset).Limit(pagination.Limit)
	}

	return query
}
