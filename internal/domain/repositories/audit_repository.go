package repositories

import (
	"context"
	"ssh-access-management/internal/domain/entities"
	"time"
)

// AuditRepository defines audit repository interface
type AuditRepository interface {
	// Audit log CRUD operations
	Create(ctx context.Context, log *entities.AuditLog) error
	GetByID(ctx context.Context, id uint) (*entities.AuditLog, error)
	List(ctx context.Context, filter AuditFilter) ([]entities.AuditLog, *PaginationResult, error)
	Delete(ctx context.Context, id uint) error

	// Audit log creation helpers
	LogUserAction(ctx context.Context, userID *uint, action entities.AuditAction, details entities.AuditDetails, ip, userAgent string) error
	LogServerAction(ctx context.Context, userID *uint, serverID uint, action entities.AuditAction, details entities.AuditDetails, ip string) error
	LogAccessAction(ctx context.Context, userID *uint, action entities.AuditAction, resourceID uint, details entities.AuditDetails, ip string) error
	LogSystemAction(ctx context.Context, action entities.AuditAction, details entities.AuditDetails) error
	LogAPIRequest(ctx context.Context, userID *uint, method, endpoint, ip, userAgent string, duration int64, status entities.AuditStatus) error

	// SSH activity logging
	LogSSHConnection(ctx context.Context, userID, serverID uint, ip, sessionID string, success bool) error
	LogSSHDisconnection(ctx context.Context, userID, serverID uint, sessionID string, duration int64) error
	LogSSHCommand(ctx context.Context, userID, serverID uint, sessionID, command string, exitCode int, duration int64) error
	LogSSHFileTransfer(ctx context.Context, userID, serverID uint, sessionID, filePath string, fileSize int64, direction string) error
	LogSSHPortForward(ctx context.Context, userID, serverID uint, sessionID string, localPort, remotePort int, remoteHost string) error

	// Security event logging
	LogSecurityEvent(ctx context.Context, userID *uint, event string, severity entities.AuditSeverity, details entities.AuditDetails, ip, userAgent string) error
	LogFailedLogin(ctx context.Context, username, ip, userAgent string, reason string) error
	LogSuccessfulLogin(ctx context.Context, userID uint, ip, userAgent string) error
	LogPasswordChange(ctx context.Context, userID uint, ip, userAgent string, forced bool) error
	LogAccountLockout(ctx context.Context, userID uint, ip, reason string) error

	// Filtering and search
	GetByUser(ctx context.Context, userID uint, filter AuditFilter) ([]entities.AuditLog, *PaginationResult, error)
	GetByServer(ctx context.Context, serverID uint, filter AuditFilter) ([]entities.AuditLog, *PaginationResult, error)
	GetByAction(ctx context.Context, action entities.AuditAction, filter AuditFilter) ([]entities.AuditLog, *PaginationResult, error)
	GetByResource(ctx context.Context, resource entities.AuditResource, filter AuditFilter) ([]entities.AuditLog, *PaginationResult, error)
	GetByDateRange(ctx context.Context, start, end time.Time, filter AuditFilter) ([]entities.AuditLog, *PaginationResult, error)
	GetSecurityEvents(ctx context.Context, filter AuditFilter) ([]entities.AuditLog, *PaginationResult, error)
	GetFailedEvents(ctx context.Context, filter AuditFilter) ([]entities.AuditLog, *PaginationResult, error)
	GetHighSeverityEvents(ctx context.Context, filter AuditFilter) ([]entities.AuditLog, *PaginationResult, error)

	// Statistics and analytics
	GetAuditStats(ctx context.Context, timeRange TimeRange) (*AuditStats, error)
	GetUserAuditStats(ctx context.Context, userID uint, timeRange TimeRange) (*UserAuditStats, error)
	GetServerAuditStats(ctx context.Context, serverID uint, timeRange TimeRange) (*ServerAuditStats, error)
	GetSecurityEventStats(ctx context.Context, timeRange TimeRange) (*SecurityEventStats, error)
	GetActivityTrends(ctx context.Context, timeRange TimeRange, granularity string) ([]ActivityTrend, error)

	// Compliance and reporting
	GetComplianceReport(ctx context.Context, start, end time.Time, filters ComplianceFilter) (*ComplianceReport, error)
	GetAccessReport(ctx context.Context, start, end time.Time) (*AccessReport, error)
	GetUserActivityReport(ctx context.Context, userID uint, start, end time.Time) (*UserActivityReport, error)
	GetServerActivityReport(ctx context.Context, serverID uint, start, end time.Time) (*ServerActivityReport, error)
	GetSecurityReport(ctx context.Context, start, end time.Time) (*SecurityReport, error)

	// Data retention and cleanup
	CleanupOldLogs(ctx context.Context, retentionDays int) (int64, error)
	ArchiveLogs(ctx context.Context, beforeDate time.Time) (int64, error)
	GetOldestLog(ctx context.Context) (*entities.AuditLog, error)
	GetStorageStats(ctx context.Context) (*StorageStats, error)

	// Export and backup
	ExportLogs(ctx context.Context, filter AuditFilter, format string) ([]byte, error)
	BackupLogs(ctx context.Context, start, end time.Time, location string) error

	// Real-time monitoring
	GetRecentActivity(ctx context.Context, limit int) ([]entities.AuditLog, error)
	GetLiveSecurityEvents(ctx context.Context, since time.Time) ([]entities.AuditLog, error)
	GetAnomalousActivities(ctx context.Context, threshold float64) ([]entities.AuditLog, error)

	// Bulk operations
	BulkCreate(ctx context.Context, logs []entities.AuditLog) error
	BulkDelete(ctx context.Context, ids []uint) error
}

// AuditFilter represents audit log filtering options
type AuditFilter struct {
	UserID          *uint
	Action          string
	Resource        string
	ResourceID      *uint
	Status          string
	Severity        string
	IPAddress       string
	SessionID       string
	RequestID       string
	Method          string
	Endpoint        string
	StartTime       *time.Time
	EndTime         *time.Time
	Search          string
	Tags            []string
	MinDuration     *int64
	MaxDuration     *int64
	HasError        *bool
	IsSecurityEvent *bool
	Pagination      PaginationParams
	SortBy          string
	SortOrder       string
}

// TimeRange represents time range for statistics
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	Days  int       `json:"days"`
}

// AuditStats represents overall audit statistics
type AuditStats struct {
	TotalLogs           int64                   `json:"total_logs"`
	LogsByAction        map[string]int64        `json:"logs_by_action"`
	LogsByResource      map[string]int64        `json:"logs_by_resource"`
	LogsByStatus        map[string]int64        `json:"logs_by_status"`
	LogsBySeverity      map[string]int64        `json:"logs_by_severity"`
	SecurityEvents      int64                   `json:"security_events"`
	FailedEvents        int64                   `json:"failed_events"`
	UniqueUsers         int64                   `json:"unique_users"`
	UniqueServers       int64                   `json:"unique_servers"`
	UniqueIPs           int64                   `json:"unique_ips"`
	AverageResponseTime float64                 `json:"average_response_time"`
	TopUsers            []UserActivitySummary   `json:"top_users"`
	TopServers          []ServerActivitySummary `json:"top_servers"`
	TopIPs              []IPActivitySummary     `json:"top_ips"`
	TimeRange           TimeRange               `json:"time_range"`
}

// UserAuditStats represents user-specific audit statistics
type UserAuditStats struct {
	UserID           uint                    `json:"user_id"`
	Username         string                  `json:"username"`
	TotalLogs        int64                   `json:"total_logs"`
	LogsByAction     map[string]int64        `json:"logs_by_action"`
	LogsByStatus     map[string]int64        `json:"logs_by_status"`
	SecurityEvents   int64                   `json:"security_events"`
	FailedEvents     int64                   `json:"failed_events"`
	ServersAccessed  int64                   `json:"servers_accessed"`
	CommandsExecuted int64                   `json:"commands_executed"`
	DataTransferred  int64                   `json:"data_transferred"`
	SessionDuration  int64                   `json:"session_duration"`
	LastActivity     *time.Time              `json:"last_activity"`
	MostUsedServers  []ServerActivitySummary `json:"most_used_servers"`
	RecentActivities []entities.AuditLog     `json:"recent_activities"`
	TimeRange        TimeRange               `json:"time_range"`
}

// ServerAuditStats represents server-specific audit statistics
type ServerAuditStats struct {
	ServerID         uint                  `json:"server_id"`
	ServerName       string                `json:"server_name"`
	TotalLogs        int64                 `json:"total_logs"`
	LogsByAction     map[string]int64      `json:"logs_by_action"`
	LogsByStatus     map[string]int64      `json:"logs_by_status"`
	SecurityEvents   int64                 `json:"security_events"`
	FailedEvents     int64                 `json:"failed_events"`
	UniqueUsers      int64                 `json:"unique_users"`
	CommandsExecuted int64                 `json:"commands_executed"`
	DataTransferred  int64                 `json:"data_transferred"`
	TotalConnections int64                 `json:"total_connections"`
	LastActivity     *time.Time            `json:"last_activity"`
	TopUsers         []UserActivitySummary `json:"top_users"`
	RecentActivities []entities.AuditLog   `json:"recent_activities"`
	TimeRange        TimeRange             `json:"time_range"`
}

// SecurityEventStats represents security event statistics
type SecurityEventStats struct {
	TotalEvents        int64               `json:"total_events"`
	EventsBySeverity   map[string]int64    `json:"events_by_severity"`
	EventsByType       map[string]int64    `json:"events_by_type"`
	FailedLogins       int64               `json:"failed_logins"`
	SuccessfulLogins   int64               `json:"successful_logins"`
	AccountLockouts    int64               `json:"account_lockouts"`
	PasswordChanges    int64               `json:"password_changes"`
	UnauthorizedAccess int64               `json:"unauthorized_access"`
	SuspiciousIPs      []IPActivitySummary `json:"suspicious_ips"`
	RiskEvents         []entities.AuditLog `json:"risk_events"`
	TimeRange          TimeRange           `json:"time_range"`
}

// ActivityTrend represents activity trend data
type ActivityTrend struct {
	Timestamp      time.Time `json:"timestamp"`
	Period         string    `json:"period"`
	TotalLogs      int64     `json:"total_logs"`
	SecurityEvents int64     `json:"security_events"`
	FailedEvents   int64     `json:"failed_events"`
	UniqueUsers    int64     `json:"unique_users"`
	UniqueServers  int64     `json:"unique_servers"`
	Commands       int64     `json:"commands"`
	DataTransfer   int64     `json:"data_transfer"`
}

// UserActivitySummary represents user activity summary
type UserActivitySummary struct {
	UserID       uint       `json:"user_id"`
	Username     string     `json:"username"`
	FullName     string     `json:"full_name"`
	LogCount     int64      `json:"log_count"`
	LastActivity *time.Time `json:"last_activity"`
}

// ServerActivitySummary represents server activity summary
type ServerActivitySummary struct {
	ServerID     uint       `json:"server_id"`
	ServerName   string     `json:"server_name"`
	ServerIP     string     `json:"server_ip"`
	LogCount     int64      `json:"log_count"`
	LastActivity *time.Time `json:"last_activity"`
}

// IPActivitySummary represents IP activity summary
type IPActivitySummary struct {
	IPAddress    string     `json:"ip_address"`
	Location     string     `json:"location"`
	LogCount     int64      `json:"log_count"`
	FailedCount  int64      `json:"failed_count"`
	LastActivity *time.Time `json:"last_activity"`
	RiskScore    float64    `json:"risk_score"`
}

// ComplianceFilter represents compliance filtering options
type ComplianceFilter struct {
	Standard       string   `json:"standard"`   // HIPAA, SOX, PCI-DSS, etc.
	Categories     []string `json:"categories"` // Access, Authentication, etc.
	Severity       string   `json:"severity"`
	IncludeSuccess bool     `json:"include_success"`
	IncludeFailure bool     `json:"include_failure"`
}

// ComplianceReport represents compliance report
type ComplianceReport struct {
	Standard        string                `json:"standard"`
	TimeRange       TimeRange             `json:"time_range"`
	TotalEvents     int64                 `json:"total_events"`
	ComplianceScore float64               `json:"compliance_score"`
	Categories      []ComplianceCategory  `json:"categories"`
	Violations      []ComplianceViolation `json:"violations"`
	Recommendations []string              `json:"recommendations"`
	GeneratedAt     time.Time             `json:"generated_at"`
}

// ComplianceCategory represents compliance category
type ComplianceCategory struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Score       float64 `json:"score"`
	EventCount  int64   `json:"event_count"`
	Status      string  `json:"status"`
}

// ComplianceViolation represents compliance violation
type ComplianceViolation struct {
	Rule        string              `json:"rule"`
	Description string              `json:"description"`
	Severity    string              `json:"severity"`
	Count       int64               `json:"count"`
	Events      []entities.AuditLog `json:"events"`
}

// AccessReport represents access report
type AccessReport struct {
	TimeRange           TimeRange               `json:"time_range"`
	TotalAccess         int64                   `json:"total_access"`
	SuccessfulAccess    int64                   `json:"successful_access"`
	FailedAccess        int64                   `json:"failed_access"`
	UniqueUsers         int64                   `json:"unique_users"`
	UniqueServers       int64                   `json:"unique_servers"`
	AccessByRole        map[string]int64        `json:"access_by_role"`
	AccessByEnvironment map[string]int64        `json:"access_by_environment"`
	TopUsers            []UserActivitySummary   `json:"top_users"`
	TopServers          []ServerActivitySummary `json:"top_servers"`
	UnusualActivities   []entities.AuditLog     `json:"unusual_activities"`
	GeneratedAt         time.Time               `json:"generated_at"`
}

// UserActivityReport represents user activity report
type UserActivityReport struct {
	UserID         uint                `json:"user_id"`
	Username       string              `json:"username"`
	FullName       string              `json:"full_name"`
	TimeRange      TimeRange           `json:"time_range"`
	Activities     []entities.AuditLog `json:"activities"`
	Summary        UserAuditStats      `json:"summary"`
	AccessPatterns []AccessPattern     `json:"access_patterns"`
	SecurityEvents []entities.AuditLog `json:"security_events"`
	GeneratedAt    time.Time           `json:"generated_at"`
}

// ServerActivityReport represents server activity report
type ServerActivityReport struct {
	ServerID       uint                `json:"server_id"`
	ServerName     string              `json:"server_name"`
	ServerIP       string              `json:"server_ip"`
	TimeRange      TimeRange           `json:"time_range"`
	Activities     []entities.AuditLog `json:"activities"`
	Summary        ServerAuditStats    `json:"summary"`
	AccessPatterns []AccessPattern     `json:"access_patterns"`
	SecurityEvents []entities.AuditLog `json:"security_events"`
	GeneratedAt    time.Time           `json:"generated_at"`
}

// SecurityReport represents security report
type SecurityReport struct {
	TimeRange       TimeRange                `json:"time_range"`
	Summary         SecurityEventStats       `json:"summary"`
	ThreatAnalysis  ThreatAnalysis           `json:"threat_analysis"`
	Incidents       []SecurityIncident       `json:"incidents"`
	Recommendations []SecurityRecommendation `json:"recommendations"`
	GeneratedAt     time.Time                `json:"generated_at"`
}

// AccessPattern represents access pattern
type AccessPattern struct {
	Pattern   string    `json:"pattern"`
	Frequency int64     `json:"frequency"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	RiskLevel string    `json:"risk_level"`
}

// ThreatAnalysis represents threat analysis
type ThreatAnalysis struct {
	RiskScore       float64             `json:"risk_score"`
	ThreatsDetected int64               `json:"threats_detected"`
	HighRiskEvents  []entities.AuditLog `json:"high_risk_events"`
	AnomaliesFound  []Anomaly           `json:"anomalies_found"`
}

// SecurityIncident represents security incident
type SecurityIncident struct {
	ID          string              `json:"id"`
	Type        string              `json:"type"`
	Severity    string              `json:"severity"`
	Description string              `json:"description"`
	StartTime   time.Time           `json:"start_time"`
	EndTime     *time.Time          `json:"end_time"`
	Status      string              `json:"status"`
	Events      []entities.AuditLog `json:"events"`
	Actions     []string            `json:"actions"`
}

// SecurityRecommendation represents security recommendation
type SecurityRecommendation struct {
	Priority    string `json:"priority"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Action      string `json:"action"`
}

// Anomaly represents detected anomaly
type Anomaly struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Confidence  float64   `json:"confidence"`
	DetectedAt  time.Time `json:"detected_at"`
	EventCount  int64     `json:"event_count"`
}

// StorageStats represents storage statistics
type StorageStats struct {
	TotalLogs     int64     `json:"total_logs"`
	TotalSize     int64     `json:"total_size_bytes"`
	OldestLog     time.Time `json:"oldest_log"`
	NewestLog     time.Time `json:"newest_log"`
	RetentionDays int       `json:"retention_days"`
	LogsToArchive int64     `json:"logs_to_archive"`
	LogsToDelete  int64     `json:"logs_to_delete"`
}

// NewTimeRange creates a new time range
func NewTimeRange(days int) TimeRange {
	end := time.Now()
	start := end.AddDate(0, 0, -days)
	return TimeRange{
		Start: start,
		End:   end,
		Days:  days,
	}
}

// NewTimeRangeFromDates creates a new time range from specific dates
func NewTimeRangeFromDates(start, end time.Time) TimeRange {
	days := int(end.Sub(start).Hours() / 24)
	return TimeRange{
		Start: start,
		End:   end,
		Days:  days,
	}
}
