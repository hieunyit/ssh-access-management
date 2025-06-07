package services

import (
	"context"
	"ssh-access-management/internal/domain/entities"
	"ssh-access-management/internal/domain/repositories"
	"time"
)

// AuditService defines audit service interface
type AuditService interface {
	// Audit Log Management
	CreateLog(ctx context.Context, req CreateAuditLogRequest) (*entities.AuditLog, error)
	GetLog(ctx context.Context, id uint) (*entities.AuditLog, error)
	ListLogs(ctx context.Context, req ListAuditLogsRequest) (*ListAuditLogsResponse, error)
	DeleteLog(ctx context.Context, id uint) error

	// Quick Logging Methods
	LogUserAction(ctx context.Context, req LogUserActionRequest) error
	LogServerAction(ctx context.Context, req LogServerActionRequest) error
	LogAccessAction(ctx context.Context, req LogAccessActionRequest) error
	LogSystemAction(ctx context.Context, req LogSystemActionRequest) error
	LogAPIRequest(ctx context.Context, req LogAPIRequestRequest) error

	// SSH Activity Logging
	LogSSHConnection(ctx context.Context, req LogSSHConnectionRequest) error
	LogSSHDisconnection(ctx context.Context, req LogSSHDisconnectionRequest) error
	LogSSHCommand(ctx context.Context, req LogSSHCommandRequest) error
	LogSSHFileTransfer(ctx context.Context, req LogSSHFileTransferRequest) error
	LogSSHPortForward(ctx context.Context, req LogSSHPortForwardRequest) error

	// Security Event Logging
	LogSecurityEvent(ctx context.Context, req LogSecurityEventRequest) error
	LogFailedLogin(ctx context.Context, req LogFailedLoginRequest) error
	LogSuccessfulLogin(ctx context.Context, req LogSuccessfulLoginRequest) error
	LogPasswordChange(ctx context.Context, req LogPasswordChangeRequest) error
	LogAccountLockout(ctx context.Context, req LogAccountLockoutRequest) error
	LogSuspiciousActivity(ctx context.Context, req LogSuspiciousActivityRequest) error

	// Filtering and Search
	GetLogsByUser(ctx context.Context, userID uint, req AuditFilterRequest) (*ListAuditLogsResponse, error)
	GetLogsByServer(ctx context.Context, serverID uint, req AuditFilterRequest) (*ListAuditLogsResponse, error)
	GetLogsByAction(ctx context.Context, action entities.AuditAction, req AuditFilterRequest) (*ListAuditLogsResponse, error)
	GetLogsByResource(ctx context.Context, resource entities.AuditResource, req AuditFilterRequest) (*ListAuditLogsResponse, error)
	GetLogsByDateRange(ctx context.Context, req DateRangeAuditRequest) (*ListAuditLogsResponse, error)
	GetSecurityEvents(ctx context.Context, req SecurityEventsRequest) (*ListAuditLogsResponse, error)
	GetFailedEvents(ctx context.Context, req AuditFilterRequest) (*ListAuditLogsResponse, error)
	GetHighSeverityEvents(ctx context.Context, req AuditFilterRequest) (*ListAuditLogsResponse, error)
	SearchLogs(ctx context.Context, req SearchAuditLogsRequest) (*ListAuditLogsResponse, error)

	// Statistics and Analytics
	GetAuditStats(ctx context.Context, req AuditStatsRequest) (*repositories.AuditStats, error)
	GetUserAuditStats(ctx context.Context, userID uint, req AuditStatsRequest) (*repositories.UserAuditStats, error)
	GetServerAuditStats(ctx context.Context, serverID uint, req AuditStatsRequest) (*repositories.ServerAuditStats, error)
	GetSecurityEventStats(ctx context.Context, req AuditStatsRequest) (*repositories.SecurityEventStats, error)
	GetActivityTrends(ctx context.Context, req ActivityTrendsRequest) ([]repositories.ActivityTrend, error)
	GetAuditDashboard(ctx context.Context, req AuditDashboardRequest) (*AuditDashboardData, error)

	// Compliance and Reporting
	GenerateComplianceReport(ctx context.Context, req ComplianceReportRequest) (*repositories.ComplianceReport, error)
	GenerateAccessReport(ctx context.Context, req AccessReportRequest) (*repositories.AccessReport, error)
	GenerateUserActivityReport(ctx context.Context, req UserActivityReportRequest) (*repositories.UserActivityReport, error)
	GenerateServerActivityReport(ctx context.Context, req ServerActivityReportRequest) (*repositories.ServerActivityReport, error)
	GenerateSecurityReport(ctx context.Context, req SecurityReportRequest) (*repositories.SecurityReport, error)
	GetComplianceScore(ctx context.Context, req ComplianceScoreRequest) (*ComplianceScoreResponse, error)

	// Data Retention and Cleanup
	CleanupOldLogs(ctx context.Context, req CleanupLogsRequest) (*CleanupResult, error)
	ArchiveLogs(ctx context.Context, req ArchiveLogsRequest) (*ArchiveResult, error)
	GetStorageStats(ctx context.Context) (*repositories.StorageStats, error)
	GetRetentionPolicy(ctx context.Context) (*RetentionPolicy, error)
	UpdateRetentionPolicy(ctx context.Context, req UpdateRetentionPolicyRequest) (*RetentionPolicy, error)

	// Export and Backup
	ExportLogs(ctx context.Context, req ExportLogsRequest) (*ExportResult, error)
	BackupLogs(ctx context.Context, req BackupLogsRequest) (*BackupResult, error)
	RestoreLogs(ctx context.Context, req RestoreLogsRequest) (*RestoreResult, error)

	// Real-time Monitoring
	GetRecentActivity(ctx context.Context, req RecentActivityRequest) (*RecentActivityResponse, error)
	GetLiveSecurityEvents(ctx context.Context, req LiveSecurityEventsRequest) (*LiveSecurityEventsResponse, error)
	GetAnomalousActivities(ctx context.Context, req AnomalousActivitiesRequest) (*AnomalousActivitiesResponse, error)
	MonitorThresholds(ctx context.Context, req MonitorThresholdsRequest) (*ThresholdMonitorResponse, error)

	// Alert Management
	CreateAlert(ctx context.Context, req CreateAlertRequest) (*AuditAlert, error)
	GetAlert(ctx context.Context, alertID string) (*AuditAlert, error)
	ListAlerts(ctx context.Context, req ListAlertsRequest) (*ListAlertsResponse, error)
	AcknowledgeAlert(ctx context.Context, alertID string, req AcknowledgeAlertRequest) error
	ResolveAlert(ctx context.Context, alertID string, req ResolveAlertRequest) error
	GetAlertRules(ctx context.Context) ([]AlertRule, error)
	CreateAlertRule(ctx context.Context, req CreateAlertRuleRequest) (*AlertRule, error)
	UpdateAlertRule(ctx context.Context, ruleID uint, req UpdateAlertRuleRequest) (*AlertRule, error)
	DeleteAlertRule(ctx context.Context, ruleID uint) error

	// Bulk Operations
	BulkCreateLogs(ctx context.Context, req BulkCreateLogsRequest) (*BulkCreateResult, error)
	BulkDeleteLogs(ctx context.Context, req BulkDeleteLogsRequest) (*BulkDeleteResult, error)
	BulkArchiveLogs(ctx context.Context, req BulkArchiveLogsRequest) (*BulkArchiveResult, error)

	// Incident Management
	CreateIncident(ctx context.Context, req CreateIncidentRequest) (*SecurityIncident, error)
	UpdateIncident(ctx context.Context, incidentID string, req UpdateIncidentRequest) (*SecurityIncident, error)
	GetIncident(ctx context.Context, incidentID string) (*SecurityIncident, error)
	ListIncidents(ctx context.Context, req ListIncidentsRequest) (*ListIncidentsResponse, error)
	CloseIncident(ctx context.Context, incidentID string, req CloseIncidentRequest) error
	GetIncidentTimeline(ctx context.Context, incidentID string) (*IncidentTimeline, error)
}

// Request/Response DTOs

type CreateAuditLogRequest struct {
	UserID     *uint                  `json:"user_id,omitempty"`
	Action     entities.AuditAction   `json:"action" validate:"required"`
	Resource   entities.AuditResource `json:"resource" validate:"required"`
	ResourceID *uint                  `json:"resource_id,omitempty"`
	Status     entities.AuditStatus   `json:"status" validate:"required"`
	Method     string                 `json:"method,omitempty"`
	Endpoint   string                 `json:"endpoint,omitempty"`
	IPAddress  string                 `json:"ip_address,omitempty"`
	UserAgent  string                 `json:"user_agent,omitempty"`
	SessionID  string                 `json:"session_id,omitempty"`
	RequestID  string                 `json:"request_id,omitempty"`
	Duration   int64                  `json:"duration,omitempty"`
	Details    entities.AuditDetails  `json:"details,omitempty"`
	Changes    entities.AuditChanges  `json:"changes,omitempty"`
	Metadata   entities.AuditMetadata `json:"metadata,omitempty"`
	Tags       []string               `json:"tags,omitempty"`
	Severity   entities.AuditSeverity `json:"severity,omitempty"`
}

type ListAuditLogsRequest struct {
	UserID          *uint      `json:"user_id,omitempty"`
	Action          string     `json:"action,omitempty"`
	Resource        string     `json:"resource,omitempty"`
	ResourceID      *uint      `json:"resource_id,omitempty"`
	Status          string     `json:"status,omitempty"`
	Severity        string     `json:"severity,omitempty"`
	IPAddress       string     `json:"ip_address,omitempty"`
	SessionID       string     `json:"session_id,omitempty"`
	RequestID       string     `json:"request_id,omitempty"`
	StartTime       *time.Time `json:"start_time,omitempty"`
	EndTime         *time.Time `json:"end_time,omitempty"`
	Search          string     `json:"search,omitempty"`
	Tags            []string   `json:"tags,omitempty"`
	MinDuration     *int64     `json:"min_duration,omitempty"`
	MaxDuration     *int64     `json:"max_duration,omitempty"`
	HasError        *bool      `json:"has_error,omitempty"`
	IsSecurityEvent *bool      `json:"is_security_event,omitempty"`
	Page            int        `json:"page,omitempty"`
	PageSize        int        `json:"page_size,omitempty"`
	SortBy          string     `json:"sort_by,omitempty"`
	SortOrder       string     `json:"sort_order,omitempty"`
}

type ListAuditLogsResponse struct {
	Logs       []entities.AuditLog            `json:"logs"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *AuditLogsSummary              `json:"summary"`
	Filters    *AppliedFilters                `json:"filters"`
}

type AuditLogsSummary struct {
	Total          int64             `json:"total"`
	ByAction       map[string]int64  `json:"by_action"`
	ByResource     map[string]int64  `json:"by_resource"`
	ByStatus       map[string]int64  `json:"by_status"`
	BySeverity     map[string]int64  `json:"by_severity"`
	SecurityEvents int64             `json:"security_events"`
	FailedEvents   int64             `json:"failed_events"`
	UniqueUsers    int64             `json:"unique_users"`
	UniqueIPs      int64             `json:"unique_ips"`
	DateRange      *DateRangeSummary `json:"date_range"`
}

type DateRangeSummary struct {
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Duration  string    `json:"duration"`
}

type AppliedFilters struct {
	UserID      *uint             `json:"user_id,omitempty"`
	Action      string            `json:"action,omitempty"`
	Resource    string            `json:"resource,omitempty"`
	Status      string            `json:"status,omitempty"`
	Severity    string            `json:"severity,omitempty"`
	DateRange   *DateRangeSummary `json:"date_range,omitempty"`
	SearchQuery string            `json:"search_query,omitempty"`
	FilterCount int               `json:"filter_count"`
}

type LogUserActionRequest struct {
	UserID    *uint                 `json:"user_id,omitempty"`
	Action    entities.AuditAction  `json:"action" validate:"required"`
	Details   entities.AuditDetails `json:"details,omitempty"`
	IPAddress string                `json:"ip_address,omitempty"`
	UserAgent string                `json:"user_agent,omitempty"`
	SessionID string                `json:"session_id,omitempty"`
	Changes   entities.AuditChanges `json:"changes,omitempty"`
}

type LogServerActionRequest struct {
	UserID    *uint                 `json:"user_id,omitempty"`
	ServerID  uint                  `json:"server_id" validate:"required"`
	Action    entities.AuditAction  `json:"action" validate:"required"`
	Details   entities.AuditDetails `json:"details,omitempty"`
	IPAddress string                `json:"ip_address,omitempty"`
	SessionID string                `json:"session_id,omitempty"`
}

type LogAccessActionRequest struct {
	UserID     *uint                 `json:"user_id,omitempty"`
	Action     entities.AuditAction  `json:"action" validate:"required"`
	ResourceID uint                  `json:"resource_id" validate:"required"`
	Details    entities.AuditDetails `json:"details,omitempty"`
	IPAddress  string                `json:"ip_address,omitempty"`
	SessionID  string                `json:"session_id,omitempty"`
}

type LogSystemActionRequest struct {
	Action    entities.AuditAction  `json:"action" validate:"required"`
	Details   entities.AuditDetails `json:"details,omitempty"`
	Component string                `json:"component,omitempty"`
	Version   string                `json:"version,omitempty"`
}

type LogAPIRequestRequest struct {
	UserID       *uint                `json:"user_id,omitempty"`
	Method       string               `json:"method" validate:"required"`
	Endpoint     string               `json:"endpoint" validate:"required"`
	IPAddress    string               `json:"ip_address,omitempty"`
	UserAgent    string               `json:"user_agent,omitempty"`
	Duration     int64                `json:"duration,omitempty"`
	Status       entities.AuditStatus `json:"status" validate:"required"`
	StatusCode   int                  `json:"status_code,omitempty"`
	RequestSize  int64                `json:"request_size,omitempty"`
	ResponseSize int64                `json:"response_size,omitempty"`
}

type LogSSHConnectionRequest struct {
	UserID     uint   `json:"user_id" validate:"required"`
	ServerID   uint   `json:"server_id" validate:"required"`
	IPAddress  string `json:"ip_address" validate:"required"`
	SessionID  string `json:"session_id" validate:"required"`
	Success    bool   `json:"success"`
	ErrorMsg   string `json:"error_msg,omitempty"`
	SSHVersion string `json:"ssh_version,omitempty"`
	ClientInfo string `json:"client_info,omitempty"`
}

type LogSSHDisconnectionRequest struct {
	UserID    uint   `json:"user_id" validate:"required"`
	ServerID  uint   `json:"server_id" validate:"required"`
	SessionID string `json:"session_id" validate:"required"`
	Duration  int64  `json:"duration"` // in seconds
	Reason    string `json:"reason,omitempty"`
	BytesIn   int64  `json:"bytes_in,omitempty"`
	BytesOut  int64  `json:"bytes_out,omitempty"`
	Commands  int    `json:"commands,omitempty"`
}

type LogSSHCommandRequest struct {
	UserID      uint              `json:"user_id" validate:"required"`
	ServerID    uint              `json:"server_id" validate:"required"`
	SessionID   string            `json:"session_id" validate:"required"`
	Command     string            `json:"command" validate:"required"`
	ExitCode    int               `json:"exit_code"`
	Duration    int64             `json:"duration"` // in milliseconds
	WorkingDir  string            `json:"working_dir,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	Output      string            `json:"output,omitempty"`
	ErrorOutput string            `json:"error_output,omitempty"`
}

type LogSSHFileTransferRequest struct {
	UserID           uint   `json:"user_id" validate:"required"`
	ServerID         uint   `json:"server_id" validate:"required"`
	SessionID        string `json:"session_id" validate:"required"`
	FilePath         string `json:"file_path" validate:"required"`
	FileSize         int64  `json:"file_size"`
	Direction        string `json:"direction" validate:"required,oneof=upload download"`
	Protocol         string `json:"protocol" validate:"required,oneof=scp sftp"`
	Success          bool   `json:"success"`
	ErrorMsg         string `json:"error_msg,omitempty"`
	Duration         int64  `json:"duration,omitempty"`
	BytesTransferred int64  `json:"bytes_transferred,omitempty"`
}

type LogSSHPortForwardRequest struct {
	UserID     uint   `json:"user_id" validate:"required"`
	ServerID   uint   `json:"server_id" validate:"required"`
	SessionID  string `json:"session_id" validate:"required"`
	LocalPort  int    `json:"local_port" validate:"required"`
	RemotePort int    `json:"remote_port" validate:"required"`
	RemoteHost string `json:"remote_host" validate:"required"`
	Direction  string `json:"direction" validate:"required,oneof=local remote"`
	Success    bool   `json:"success"`
	ErrorMsg   string `json:"error_msg,omitempty"`
	Duration   int64  `json:"duration,omitempty"`
}

type LogSecurityEventRequest struct {
	UserID      *uint                  `json:"user_id,omitempty"`
	Event       string                 `json:"event" validate:"required"`
	Severity    entities.AuditSeverity `json:"severity" validate:"required"`
	Details     entities.AuditDetails  `json:"details,omitempty"`
	IPAddress   string                 `json:"ip_address,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	ThreatLevel string                 `json:"threat_level,omitempty"`
	Mitigated   bool                   `json:"mitigated,omitempty"`
}

type LogFailedLoginRequest struct {
	Username      string `json:"username" validate:"required"`
	IPAddress     string `json:"ip_address" validate:"required"`
	UserAgent     string `json:"user_agent,omitempty"`
	Reason        string `json:"reason" validate:"required"`
	AttemptCount  int    `json:"attempt_count,omitempty"`
	AccountLocked bool   `json:"account_locked,omitempty"`
}

type LogSuccessfulLoginRequest struct {
	UserID    uint   `json:"user_id" validate:"required"`
	IPAddress string `json:"ip_address" validate:"required"`
	UserAgent string `json:"user_agent,omitempty"`
	Method    string `json:"method,omitempty"` // password, sso, mfa
	SessionID string `json:"session_id,omitempty"`
	Location  string `json:"location,omitempty"`
}

type LogPasswordChangeRequest struct {
	UserID    uint   `json:"user_id" validate:"required"`
	IPAddress string `json:"ip_address" validate:"required"`
	UserAgent string `json:"user_agent,omitempty"`
	Forced    bool   `json:"forced,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

type LogAccountLockoutRequest struct {
	UserID      uint   `json:"user_id" validate:"required"`
	IPAddress   string `json:"ip_address" validate:"required"`
	Reason      string `json:"reason" validate:"required"`
	Duration    int64  `json:"duration,omitempty"` // in seconds
	LockedBy    *uint  `json:"locked_by,omitempty"`
	AutoLockout bool   `json:"auto_lockout,omitempty"`
}

type LogSuspiciousActivityRequest struct {
	UserID       *uint                  `json:"user_id,omitempty"`
	ActivityType string                 `json:"activity_type" validate:"required"`
	Description  string                 `json:"description" validate:"required"`
	Severity     entities.AuditSeverity `json:"severity" validate:"required"`
	IPAddress    string                 `json:"ip_address,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	Indicators   []string               `json:"indicators,omitempty"`
	RiskScore    float64                `json:"risk_score,omitempty"`
	Mitigated    bool                   `json:"mitigated,omitempty"`
}

type AuditFilterRequest struct {
	StartTime       *time.Time `json:"start_time,omitempty"`
	EndTime         *time.Time `json:"end_time,omitempty"`
	Status          string     `json:"status,omitempty"`
	Severity        string     `json:"severity,omitempty"`
	IsSecurityEvent *bool      `json:"is_security_event,omitempty"`
	Page            int        `json:"page,omitempty"`
	PageSize        int        `json:"page_size,omitempty"`
	SortBy          string     `json:"sort_by,omitempty"`
	SortOrder       string     `json:"sort_order,omitempty"`
}

type DateRangeAuditRequest struct {
	StartTime *time.Time `json:"start_time" validate:"required"`
	EndTime   *time.Time `json:"end_time" validate:"required"`
	AuditFilterRequest
}

type SecurityEventsRequest struct {
	MinSeverity    entities.AuditSeverity `json:"min_severity,omitempty"`
	ThreatLevel    string                 `json:"threat_level,omitempty"`
	OnlyUnresolved bool                   `json:"only_unresolved,omitempty"`
	AuditFilterRequest
}

type SearchAuditLogsRequest struct {
	Query      string   `json:"query" validate:"required"`
	SearchType string   `json:"search_type,omitempty" validate:"omitempty,oneof=simple advanced regex"`
	SearchIn   []string `json:"search_in,omitempty"` // fields to search in
	Highlights bool     `json:"highlights,omitempty"`
	AuditFilterRequest
}

type AuditStatsRequest struct {
	TimeRange   repositories.TimeRange `json:"time_range"`
	Granularity string                 `json:"granularity,omitempty" validate:"omitempty,oneof=hour day week month"`
	GroupBy     []string               `json:"group_by,omitempty"`
	Filters     map[string]string      `json:"filters,omitempty"`
}

type ActivityTrendsRequest struct {
	TimeRange   repositories.TimeRange  `json:"time_range"`
	Granularity string                  `json:"granularity" validate:"required,oneof=hour day week month"`
	Metrics     []string                `json:"metrics,omitempty"`
	CompareWith *repositories.TimeRange `json:"compare_with,omitempty"`
}

type AuditDashboardRequest struct {
	UserID      *uint                  `json:"user_id,omitempty"`
	TimeRange   repositories.TimeRange `json:"time_range"`
	Widgets     []string               `json:"widgets,omitempty"`
	RefreshRate int                    `json:"refresh_rate,omitempty"` // in seconds
}

type AuditDashboardData struct {
	Summary        *repositories.AuditStats             `json:"summary"`
	RecentActivity []entities.AuditLog                  `json:"recent_activity"`
	SecurityEvents []entities.AuditLog                  `json:"security_events"`
	TopUsers       []repositories.UserActivitySummary   `json:"top_users"`
	TopServers     []repositories.ServerActivitySummary `json:"top_servers"`
	TopIPs         []repositories.IPActivitySummary     `json:"top_ips"`
	Trends         []repositories.ActivityTrend         `json:"trends"`
	Alerts         []AuditAlert                         `json:"alerts"`
	Incidents      []SecurityIncident                   `json:"incidents"`
	UpdatedAt      string                               `json:"updated_at"`
}

type ComplianceReportRequest struct {
	Standard       string                 `json:"standard" validate:"required"`
	TimeRange      repositories.TimeRange `json:"time_range"`
	Categories     []string               `json:"categories,omitempty"`
	Severity       string                 `json:"severity,omitempty"`
	IncludeSuccess bool                   `json:"include_success,omitempty"`
	IncludeFailure bool                   `json:"include_failure,omitempty"`
	Format         string                 `json:"format" validate:"required,oneof=json pdf excel"`
}

type AccessReportRequest struct {
	TimeRange      repositories.TimeRange `json:"time_range"`
	UserIDs        []uint                 `json:"user_ids,omitempty"`
	ServerIDs      []uint                 `json:"server_ids,omitempty"`
	Environment    string                 `json:"environment,omitempty"`
	IncludeDetails bool                   `json:"include_details,omitempty"`
	Format         string                 `json:"format" validate:"required,oneof=json pdf excel"`
}

type UserActivityReportRequest struct {
	UserID          uint                   `json:"user_id" validate:"required"`
	TimeRange       repositories.TimeRange `json:"time_range"`
	IncludeDetails  bool                   `json:"include_details,omitempty"`
	IncludeSessions bool                   `json:"include_sessions,omitempty"`
	Format          string                 `json:"format" validate:"required,oneof=json pdf excel"`
}

type ServerActivityReportRequest struct {
	ServerID        uint                   `json:"server_id" validate:"required"`
	TimeRange       repositories.TimeRange `json:"time_range"`
	IncludeDetails  bool                   `json:"include_details,omitempty"`
	IncludeSessions bool                   `json:"include_sessions,omitempty"`
	Format          string                 `json:"format" validate:"required,oneof=json pdf excel"`
}

type SecurityReportRequest struct {
	TimeRange             repositories.TimeRange `json:"time_range"`
	MinSeverity           entities.AuditSeverity `json:"min_severity,omitempty"`
	IncludeIncidents      bool                   `json:"include_incidents,omitempty"`
	IncludeThreatAnalysis bool                   `json:"include_threat_analysis,omitempty"`
	Format                string                 `json:"format" validate:"required,oneof=json pdf excel"`
}

type ComplianceScoreRequest struct {
	Standard  string                 `json:"standard" validate:"required"`
	TimeRange repositories.TimeRange `json:"time_range"`
	Scope     string                 `json:"scope,omitempty"` // organization, department, user
	ScopeID   *uint                  `json:"scope_id,omitempty"`
}

type ComplianceScoreResponse struct {
	Standard        string                             `json:"standard"`
	OverallScore    float64                            `json:"overall_score"`
	CategoryScores  map[string]float64                 `json:"category_scores"`
	TimeRange       repositories.TimeRange             `json:"time_range"`
	Violations      []repositories.ComplianceViolation `json:"violations"`
	Trends          []ComplianceScoreTrend             `json:"trends"`
	Recommendations []string                           `json:"recommendations"`
	LastUpdated     string                             `json:"last_updated"`
}

type ComplianceScoreTrend struct {
	Date  string  `json:"date"`
	Score float64 `json:"score"`
}

type CleanupLogsRequest struct {
	RetentionDays int      `json:"retention_days" validate:"required,min=1"`
	Categories    []string `json:"categories,omitempty"`
	DryRun        bool     `json:"dry_run,omitempty"`
	BatchSize     int      `json:"batch_size,omitempty"`
}

type CleanupResult struct {
	ProcessedLogs int64    `json:"processed_logs"`
	DeletedLogs   int64    `json:"deleted_logs"`
	FreedSpace    int64    `json:"freed_space_bytes"`
	Duration      int64    `json:"duration_ms"`
	Errors        []string `json:"errors,omitempty"`
	WasDryRun     bool     `json:"was_dry_run"`
}

type ArchiveLogsRequest struct {
	BeforeDate    time.Time `json:"before_date" validate:"required"`
	ArchiveFormat string    `json:"archive_format" validate:"required,oneof=gzip bzip2 lz4"`
	Destination   string    `json:"destination" validate:"required"`
	Compress      bool      `json:"compress"`
	Verify        bool      `json:"verify"`
}

type ArchiveResult struct {
	ArchivedLogs     int64    `json:"archived_logs"`
	ArchiveSize      int64    `json:"archive_size_bytes"`
	ArchiveFiles     []string `json:"archive_files"`
	Duration         int64    `json:"duration_ms"`
	CompressionRatio float64  `json:"compression_ratio"`
	Verified         bool     `json:"verified"`
	Errors           []string `json:"errors,omitempty"`
}

type ExportLogsRequest struct {
	Filter     ListAuditLogsRequest `json:"filter"`
	Format     string               `json:"format" validate:"required,oneof=json csv excel"`
	Fields     []string             `json:"fields,omitempty"`
	Compressed bool                 `json:"compressed,omitempty"`
	MaxRecords int                  `json:"max_records,omitempty"`
}

type ExportResult struct {
	FileName    string `json:"file_name"`
	FileSize    int64  `json:"file_size_bytes"`
	RecordCount int64  `json:"record_count"`
	Format      string `json:"format"`
	Compressed  bool   `json:"compressed"`
	DownloadURL string `json:"download_url"`
	ExpiresAt   string `json:"expires_at"`
	Duration    int64  `json:"duration_ms"`
}

type BackupLogsRequest struct {
	TimeRange   repositories.TimeRange `json:"time_range"`
	Destination string                 `json:"destination" validate:"required"`
	Incremental bool                   `json:"incremental,omitempty"`
	Encrypted   bool                   `json:"encrypted,omitempty"`
	Verify      bool                   `json:"verify,omitempty"`
}

type BackupResult struct {
	BackupFiles   []string `json:"backup_files"`
	TotalSize     int64    `json:"total_size_bytes"`
	LogsBackedUp  int64    `json:"logs_backed_up"`
	IsIncremental bool     `json:"is_incremental"`
	IsEncrypted   bool     `json:"is_encrypted"`
	BackupID      string   `json:"backup_id"`
	Duration      int64    `json:"duration_ms"`
	Verified      bool     `json:"verified"`
}

type RestoreLogsRequest struct {
	BackupID    string                  `json:"backup_id" validate:"required"`
	TimeRange   *repositories.TimeRange `json:"time_range,omitempty"`
	Destination string                  `json:"destination,omitempty"`
	Verify      bool                    `json:"verify,omitempty"`
	DryRun      bool                    `json:"dry_run,omitempty"`
}

type RestoreResult struct {
	RestoredLogs int64    `json:"restored_logs"`
	Duration     int64    `json:"duration_ms"`
	Verified     bool     `json:"verified"`
	WasDryRun    bool     `json:"was_dry_run"`
	Errors       []string `json:"errors,omitempty"`
}

type RecentActivityRequest struct {
	Limit       int                    `json:"limit,omitempty" validate:"omitempty,min=1,max=1000"`
	MinSeverity entities.AuditSeverity `json:"min_severity,omitempty"`
	Actions     []string               `json:"actions,omitempty"`
	Resources   []string               `json:"resources,omitempty"`
	Since       *time.Time             `json:"since,omitempty"`
}

type RecentActivityResponse struct {
	Activities []entities.AuditLog    `json:"activities"`
	Summary    *RecentActivitySummary `json:"summary"`
	UpdatedAt  string                 `json:"updated_at"`
}

type RecentActivitySummary struct {
	TotalActivities int64            `json:"total_activities"`
	SecurityEvents  int64            `json:"security_events"`
	FailedEvents    int64            `json:"failed_events"`
	ByAction        map[string]int64 `json:"by_action"`
	BySeverity      map[string]int64 `json:"by_severity"`
	LastActivity    *time.Time       `json:"last_activity,omitempty"`
}

type LiveSecurityEventsRequest struct {
	Since       time.Time              `json:"since" validate:"required"`
	MinSeverity entities.AuditSeverity `json:"min_severity,omitempty"`
	EventTypes  []string               `json:"event_types,omitempty"`
	UserIDs     []uint                 `json:"user_ids,omitempty"`
}

type LiveSecurityEventsResponse struct {
	Events    []entities.AuditLog    `json:"events"`
	Summary   *SecurityEventsSummary `json:"summary"`
	UpdatedAt string                 `json:"updated_at"`
}

type SecurityEventsSummary struct {
	TotalEvents    int64            `json:"total_events"`
	CriticalEvents int64            `json:"critical_events"`
	HighEvents     int64            `json:"high_events"`
	NewThreats     int64            `json:"new_threats"`
	ByType         map[string]int64 `json:"by_type"`
	MostActiveIPs  []string         `json:"most_active_ips"`
	ThreatLevel    string           `json:"threat_level"`
}

type AnomalousActivitiesRequest struct {
	Threshold   float64                `json:"threshold" validate:"required,min=0,max=1"`
	TimeWindow  int                    `json:"time_window,omitempty"` // hours
	Algorithm   string                 `json:"algorithm,omitempty" validate:"omitempty,oneof=statistical ml pattern"`
	Categories  []string               `json:"categories,omitempty"`
	MinSeverity entities.AuditSeverity `json:"min_severity,omitempty"`
}

type AnomalousActivitiesResponse struct {
	Anomalies []repositories.Anomaly `json:"anomalies"`
	Summary   *AnomaliesSummary      `json:"summary"`
	Algorithm string                 `json:"algorithm"`
	Threshold float64                `json:"threshold"`
	UpdatedAt string                 `json:"updated_at"`
}

type AnomaliesSummary struct {
	TotalAnomalies   int64    `json:"total_anomalies"`
	HighConfidence   int64    `json:"high_confidence"`
	MediumConfidence int64    `json:"medium_confidence"`
	LowConfidence    int64    `json:"low_confidence"`
	AvgConfidence    float64  `json:"avg_confidence"`
	TopCategories    []string `json:"top_categories"`
}

type MonitorThresholdsRequest struct {
	Metrics    []string `json:"metrics" validate:"required"`
	TimeWindow int      `json:"time_window,omitempty"` // minutes
	Alerting   bool     `json:"alerting,omitempty"`
}

type ThresholdMonitorResponse struct {
	Metrics   []ThresholdMetric `json:"metrics"`
	Alerts    []ThresholdAlert  `json:"alerts"`
	Status    string            `json:"status"`
	UpdatedAt string            `json:"updated_at"`
}

type ThresholdMetric struct {
	Name        string  `json:"name"`
	Value       float64 `json:"value"`
	Threshold   float64 `json:"threshold"`
	Status      string  `json:"status"` // normal, warning, critical
	Trend       string  `json:"trend"`  // up, down, stable
	LastUpdated string  `json:"last_updated"`
}

type ThresholdAlert struct {
	ID          string  `json:"id"`
	Metric      string  `json:"metric"`
	Value       float64 `json:"value"`
	Threshold   float64 `json:"threshold"`
	Severity    string  `json:"severity"`
	Message     string  `json:"message"`
	TriggeredAt string  `json:"triggered_at"`
	IsActive    bool    `json:"is_active"`
}

type AuditAlert struct {
	ID             string                 `json:"id"`
	Type           string                 `json:"type"`
	Severity       entities.AuditSeverity `json:"severity"`
	Title          string                 `json:"title"`
	Message        string                 `json:"message"`
	Status         string                 `json:"status"` // new, acknowledged, resolved
	UserID         *uint                  `json:"user_id,omitempty"`
	ServerID       *uint                  `json:"server_id,omitempty"`
	TriggeredBy    string                 `json:"triggered_by"`
	TriggeredAt    string                 `json:"triggered_at"`
	AcknowledgedAt *string                `json:"acknowledged_at,omitempty"`
	AcknowledgedBy *uint                  `json:"acknowledged_by,omitempty"`
	ResolvedAt     *string                `json:"resolved_at,omitempty"`
	ResolvedBy     *uint                  `json:"resolved_by,omitempty"`
	RelatedLogs    []uint                 `json:"related_logs,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

type CreateAlertRequest struct {
	Type        string                 `json:"type" validate:"required"`
	Severity    entities.AuditSeverity `json:"severity" validate:"required"`
	Title       string                 `json:"title" validate:"required"`
	Message     string                 `json:"message" validate:"required"`
	UserID      *uint                  `json:"user_id,omitempty"`
	ServerID    *uint                  `json:"server_id,omitempty"`
	TriggeredBy string                 `json:"triggered_by" validate:"required"`
	RelatedLogs []uint                 `json:"related_logs,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type ListAlertsRequest struct {
	Type      string                 `json:"type,omitempty"`
	Severity  entities.AuditSeverity `json:"severity,omitempty"`
	Status    string                 `json:"status,omitempty"`
	UserID    *uint                  `json:"user_id,omitempty"`
	ServerID  *uint                  `json:"server_id,omitempty"`
	Since     *time.Time             `json:"since,omitempty"`
	Page      int                    `json:"page,omitempty"`
	PageSize  int                    `json:"page_size,omitempty"`
	SortBy    string                 `json:"sort_by,omitempty"`
	SortOrder string                 `json:"sort_order,omitempty"`
}

type ListAlertsResponse struct {
	Alerts     []AuditAlert                   `json:"alerts"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *AlertsSummary                 `json:"summary"`
}

type AlertsSummary struct {
	Total        int64            `json:"total"`
	New          int64            `json:"new"`
	Acknowledged int64            `json:"acknowledged"`
	Resolved     int64            `json:"resolved"`
	BySeverity   map[string]int64 `json:"by_severity"`
	ByType       map[string]int64 `json:"by_type"`
}

type AcknowledgeAlertRequest struct {
	Comments string `json:"comments,omitempty"`
}

type ResolveAlertRequest struct {
	Resolution string `json:"resolution" validate:"required"`
	Comments   string `json:"comments,omitempty"`
}

type AlertRule struct {
	ID          uint            `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Type        string          `json:"type"`
	Conditions  AlertConditions `json:"conditions"`
	Actions     AlertActions    `json:"actions"`
	IsActive    bool            `json:"is_active"`
	Priority    int             `json:"priority"`
	CreatedBy   uint            `json:"created_by"`
	CreatedAt   string          `json:"created_at"`
	UpdatedAt   string          `json:"updated_at"`
}

type AlertConditions struct {
	Filters    map[string]interface{} `json:"filters"`
	Thresholds map[string]float64     `json:"thresholds"`
	TimeWindow int                    `json:"time_window"` // minutes
	Frequency  int                    `json:"frequency"`   // check frequency in minutes
}

type AlertActions struct {
	CreateAlert     bool                `json:"create_alert"`
	SendEmail       bool                `json:"send_email"`
	SendSlack       bool                `json:"send_slack"`
	RunWebhook      bool                `json:"run_webhook"`
	EmailRecipients []string            `json:"email_recipients,omitempty"`
	SlackChannel    string              `json:"slack_channel,omitempty"`
	WebhookURL      string              `json:"webhook_url,omitempty"`
	CustomActions   []CustomAlertAction `json:"custom_actions,omitempty"`
}

type CustomAlertAction struct {
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config"`
}

type CreateAlertRuleRequest struct {
	Name        string          `json:"name" validate:"required"`
	Description string          `json:"description,omitempty"`
	Type        string          `json:"type" validate:"required"`
	Conditions  AlertConditions `json:"conditions" validate:"required"`
	Actions     AlertActions    `json:"actions" validate:"required"`
	IsActive    bool            `json:"is_active"`
	Priority    int             `json:"priority"`
}

type UpdateAlertRuleRequest struct {
	Name        *string          `json:"name,omitempty"`
	Description *string          `json:"description,omitempty"`
	Type        *string          `json:"type,omitempty"`
	Conditions  *AlertConditions `json:"conditions,omitempty"`
	Actions     *AlertActions    `json:"actions,omitempty"`
	IsActive    *bool            `json:"is_active,omitempty"`
	Priority    *int             `json:"priority,omitempty"`
}

type BulkCreateLogsRequest struct {
	Logs []CreateAuditLogRequest `json:"logs" validate:"required,min=1,max=1000"`
}

type BulkCreateResult struct {
	TotalRequested int64    `json:"total_requested"`
	Successful     int64    `json:"successful"`
	Failed         int64    `json:"failed"`
	Errors         []string `json:"errors,omitempty"`
	Duration       int64    `json:"duration_ms"`
}

type BulkDeleteLogsRequest struct {
	LogIDs []uint `json:"log_ids" validate:"required,min=1,max=1000"`
	Force  bool   `json:"force,omitempty"`
}

type BulkDeleteResult struct {
	TotalRequested int64    `json:"total_requested"`
	Deleted        int64    `json:"deleted"`
	Failed         int64    `json:"failed"`
	Errors         []string `json:"errors,omitempty"`
	Duration       int64    `json:"duration_ms"`
}

type BulkArchiveLogsRequest struct {
	Filter      ListAuditLogsRequest `json:"filter"`
	Destination string               `json:"destination" validate:"required"`
	DeleteAfter bool                 `json:"delete_after,omitempty"`
}

type BulkArchiveResult struct {
	ProcessedLogs int64    `json:"processed_logs"`
	ArchivedLogs  int64    `json:"archived_logs"`
	DeletedLogs   int64    `json:"deleted_logs,omitempty"`
	ArchiveFiles  []string `json:"archive_files"`
	Duration      int64    `json:"duration_ms"`
	Errors        []string `json:"errors,omitempty"`
}

type SecurityIncident struct {
	ID            string                  `json:"id"`
	Type          string                  `json:"type"`
	Severity      entities.AuditSeverity  `json:"severity"`
	Title         string                  `json:"title"`
	Description   string                  `json:"description"`
	Status        string                  `json:"status"` // open, investigating, resolved, closed
	Priority      string                  `json:"priority"`
	AssignedTo    *uint                   `json:"assigned_to,omitempty"`
	ReportedBy    uint                    `json:"reported_by"`
	StartTime     time.Time               `json:"start_time"`
	EndTime       *time.Time              `json:"end_time,omitempty"`
	Impact        string                  `json:"impact"`
	Resolution    string                  `json:"resolution,omitempty"`
	RelatedLogs   []uint                  `json:"related_logs"`
	RelatedAlerts []string                `json:"related_alerts"`
	Evidence      []IncidentEvidence      `json:"evidence"`
	Timeline      []IncidentTimelineEntry `json:"timeline"`
	Tags          []string                `json:"tags"`
	Metadata      map[string]interface{}  `json:"metadata"`
	CreatedAt     string                  `json:"created_at"`
	UpdatedAt     string                  `json:"updated_at"`
}

type CreateIncidentRequest struct {
	Type          string                 `json:"type" validate:"required"`
	Severity      entities.AuditSeverity `json:"severity" validate:"required"`
	Title         string                 `json:"title" validate:"required"`
	Description   string                 `json:"description" validate:"required"`
	Priority      string                 `json:"priority" validate:"required"`
	StartTime     time.Time              `json:"start_time" validate:"required"`
	Impact        string                 `json:"impact" validate:"required"`
	RelatedLogs   []uint                 `json:"related_logs,omitempty"`
	RelatedAlerts []string               `json:"related_alerts,omitempty"`
	Tags          []string               `json:"tags,omitempty"`
}

type UpdateIncidentRequest struct {
	Status     *string    `json:"status,omitempty"`
	Priority   *string    `json:"priority,omitempty"`
	AssignedTo *uint      `json:"assigned_to,omitempty"`
	EndTime    *time.Time `json:"end_time,omitempty"`
	Resolution *string    `json:"resolution,omitempty"`
	Tags       []string   `json:"tags,omitempty"`
}

type CloseIncidentRequest struct {
	Resolution string `json:"resolution" validate:"required"`
	Comments   string `json:"comments,omitempty"`
}

type ListIncidentsRequest struct {
	Type       string                 `json:"type,omitempty"`
	Severity   entities.AuditSeverity `json:"severity,omitempty"`
	Status     string                 `json:"status,omitempty"`
	Priority   string                 `json:"priority,omitempty"`
	AssignedTo *uint                  `json:"assigned_to,omitempty"`
	ReportedBy *uint                  `json:"reported_by,omitempty"`
	Since      *time.Time             `json:"since,omitempty"`
	Page       int                    `json:"page,omitempty"`
	PageSize   int                    `json:"page_size,omitempty"`
	SortBy     string                 `json:"sort_by,omitempty"`
	SortOrder  string                 `json:"sort_order,omitempty"`
}

type ListIncidentsResponse struct {
	Incidents  []SecurityIncident             `json:"incidents"`
	Pagination *repositories.PaginationResult `json:"pagination"`
	Summary    *IncidentsSummary              `json:"summary"`
}

type IncidentsSummary struct {
	Total         int64            `json:"total"`
	Open          int64            `json:"open"`
	Investigating int64            `json:"investigating"`
	Resolved      int64            `json:"resolved"`
	Closed        int64            `json:"closed"`
	BySeverity    map[string]int64 `json:"by_severity"`
	ByType        map[string]int64 `json:"by_type"`
	ByPriority    map[string]int64 `json:"by_priority"`
}

type IncidentTimeline struct {
	IncidentID string                  `json:"incident_id"`
	Timeline   []IncidentTimelineEntry `json:"timeline"`
	Summary    *TimelineSummary        `json:"summary"`
}

type IncidentTimelineEntry struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"` // action, update, comment, evidence
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	UserID      *uint                  `json:"user_id,omitempty"`
	Username    string                 `json:"username,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type TimelineSummary struct {
	TotalEntries int64            `json:"total_entries"`
	FirstEntry   *time.Time       `json:"first_entry,omitempty"`
	LastEntry    *time.Time       `json:"last_entry,omitempty"`
	Duration     string           `json:"duration,omitempty"`
	ByType       map[string]int64 `json:"by_type"`
}

type IncidentEvidence struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"` // log, file, screenshot, etc.
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	URL         string                 `json:"url,omitempty"`
	Hash        string                 `json:"hash,omitempty"`
	Size        int64                  `json:"size,omitempty"`
	CollectedBy uint                   `json:"collected_by"`
	CollectedAt time.Time              `json:"collected_at"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type RetentionPolicy struct {
	ID            uint                   `json:"id"`
	Name          string                 `json:"name"`
	RetentionDays int                    `json:"retention_days"`
	ArchiveDays   int                    `json:"archive_days"`
	Categories    []string               `json:"categories"`
	MinSeverity   entities.AuditSeverity `json:"min_severity"`
	AutoDelete    bool                   `json:"auto_delete"`
	AutoArchive   bool                   `json:"auto_archive"`
	IsActive      bool                   `json:"is_active"`
	CreatedAt     string                 `json:"created_at"`
	UpdatedAt     string                 `json:"updated_at"`
}

type UpdateRetentionPolicyRequest struct {
	RetentionDays *int                    `json:"retention_days,omitempty"`
	ArchiveDays   *int                    `json:"archive_days,omitempty"`
	Categories    []string                `json:"categories,omitempty"`
	MinSeverity   *entities.AuditSeverity `json:"min_severity,omitempty"`
	AutoDelete    *bool                   `json:"auto_delete,omitempty"`
	AutoArchive   *bool                   `json:"auto_archive,omitempty"`
	IsActive      *bool                   `json:"is_active,omitempty"`
}
