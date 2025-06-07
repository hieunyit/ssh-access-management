package dto

import (
	"ssh-access-management/internal/domain/repositories"
)

// PaginationRequest represents common pagination request
type PaginationRequest struct {
	Page      int    `json:"page,omitempty" validate:"omitempty,min=1"`
	PageSize  int    `json:"page_size,omitempty" validate:"omitempty,min=1,max=100"`
	SortBy    string `json:"sort_by,omitempty"`
	SortOrder string `json:"sort_order,omitempty" validate:"omitempty,oneof=asc desc"`
}

// SearchRequest represents common search request
type SearchRequest struct {
	Query string `json:"query" validate:"required,min=1"`
	PaginationRequest
}

// FilterRequest represents common filter request
type FilterRequest struct {
	StartDate *string `json:"start_date,omitempty"`
	EndDate   *string `json:"end_date,omitempty"`
	Status    string  `json:"status,omitempty"`
	PaginationRequest
}

// BulkOperationRequest represents bulk operation request
type BulkOperationRequest struct {
	IDs    []uint                 `json:"ids" validate:"required,min=1,max=1000"`
	Action string                 `json:"action" validate:"required"`
	Params map[string]interface{} `json:"params,omitempty"`
}

// BulkOperationResponse represents bulk operation response
type BulkOperationResponse struct {
	TotalRequested int                  `json:"total_requested"`
	Successful     int                  `json:"successful"`
	Failed         int                  `json:"failed"`
	Errors         []BulkOperationError `json:"errors,omitempty"`
	Results        []interface{}        `json:"results,omitempty"`
}

// BulkOperationError represents error in bulk operation
type BulkOperationError struct {
	Index   int    `json:"index"`
	ID      *uint  `json:"id,omitempty"`
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

// ImportRequest represents data import request
type ImportRequest struct {
	Data    []byte            `json:"data" validate:"required"`
	Format  string            `json:"format" validate:"required,oneof=csv json xlsx"`
	Options map[string]string `json:"options,omitempty"`
	DryRun  bool              `json:"dry_run,omitempty"`
}

// ImportResponse represents data import response
type ImportResponse struct {
	TotalRows      int             `json:"total_rows"`
	ProcessedRows  int             `json:"processed_rows"`
	SuccessfulRows int             `json:"successful_rows"`
	FailedRows     int             `json:"failed_rows"`
	SkippedRows    int             `json:"skipped_rows"`
	Errors         []ImportError   `json:"errors,omitempty"`
	Warnings       []ImportWarning `json:"warnings,omitempty"`
	Summary        map[string]int  `json:"summary"`
	PreviewData    []interface{}   `json:"preview_data,omitempty"`
}

// ImportError represents error during import
type ImportError struct {
	Row     int               `json:"row"`
	Column  string            `json:"column,omitempty"`
	Field   string            `json:"field,omitempty"`
	Value   interface{}       `json:"value,omitempty"`
	Message string            `json:"message"`
	Code    string            `json:"code,omitempty"`
	Data    map[string]string `json:"data,omitempty"`
}

// ImportWarning represents warning during import
type ImportWarning struct {
	Row     int               `json:"row"`
	Message string            `json:"message"`
	Field   string            `json:"field,omitempty"`
	Data    map[string]string `json:"data,omitempty"`
}

// ExportRequest represents data export request
type ExportRequest struct {
	Format   string                 `json:"format" validate:"required,oneof=csv json xlsx pdf"`
	Filter   map[string]interface{} `json:"filter,omitempty"`
	Fields   []string               `json:"fields,omitempty"`
	Options  map[string]string      `json:"options,omitempty"`
	Template string                 `json:"template,omitempty"`
}

// ExportResponse represents data export response
type ExportResponse struct {
	Data        []byte            `json:"data"`
	Filename    string            `json:"filename"`
	ContentType string            `json:"content_type"`
	Size        int64             `json:"size"`
	RecordCount int               `json:"record_count"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// HealthCheckResponse represents health check response
type HealthCheckResponse struct {
	Status      string                   `json:"status"`
	Version     string                   `json:"version"`
	Timestamp   string                   `json:"timestamp"`
	Services    map[string]ServiceHealth `json:"services"`
	Uptime      string                   `json:"uptime"`
	Environment string                   `json:"environment"`
}

// ServiceHealth represents individual service health
type ServiceHealth struct {
	Status       string            `json:"status"`
	Message      string            `json:"message,omitempty"`
	ResponseTime string            `json:"response_time,omitempty"`
	LastChecked  string            `json:"last_checked"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// MetricsResponse represents system metrics response
type MetricsResponse struct {
	System    SystemMetrics   `json:"system"`
	Database  DatabaseMetrics `json:"database"`
	API       APIMetrics      `json:"api"`
	Security  SecurityMetrics `json:"security"`
	Timestamp string          `json:"timestamp"`
}

// SystemMetrics represents system-level metrics
type SystemMetrics struct {
	CPUUsage    float64 `json:"cpu_usage"`
	MemoryUsage float64 `json:"memory_usage"`
	DiskUsage   float64 `json:"disk_usage"`
	NetworkIn   int64   `json:"network_in"`
	NetworkOut  int64   `json:"network_out"`
	Uptime      string  `json:"uptime"`
	GoRoutines  int     `json:"goroutines"`
	GCPauses    int64   `json:"gc_pauses"`
}

// DatabaseMetrics represents database metrics
type DatabaseMetrics struct {
	Connections     int     `json:"connections"`
	ActiveQueries   int     `json:"active_queries"`
	AvgQueryTime    float64 `json:"avg_query_time"`
	SlowQueries     int64   `json:"slow_queries"`
	DatabaseSize    int64   `json:"database_size"`
	TableCount      int     `json:"table_count"`
	IndexEfficiency float64 `json:"index_efficiency"`
}

// APIMetrics represents API metrics
type APIMetrics struct {
	RequestsPerMinute int     `json:"requests_per_minute"`
	AvgResponseTime   float64 `json:"avg_response_time"`
	ErrorRate         float64 `json:"error_rate"`
	ActiveSessions    int     `json:"active_sessions"`
	CacheHitRate      float64 `json:"cache_hit_rate"`
	RateLimitHits     int64   `json:"rate_limit_hits"`
}

// SecurityMetrics represents security metrics
type SecurityMetrics struct {
	FailedLogins      int64  `json:"failed_logins"`
	SuspiciousIPs     int    `json:"suspicious_ips"`
	BlockedRequests   int64  `json:"blocked_requests"`
	ActiveSessions    int    `json:"active_sessions"`
	SecurityIncidents int    `json:"security_incidents"`
	LastSecurityScan  string `json:"last_security_scan"`
}

// AuditQuery represents audit query request
type AuditQuery struct {
	UserID      *uint    `json:"user_id,omitempty"`
	Action      string   `json:"action,omitempty"`
	Resource    string   `json:"resource,omitempty"`
	ResourceID  *uint    `json:"resource_id,omitempty"`
	Status      string   `json:"status,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	IPAddress   string   `json:"ip_address,omitempty"`
	SessionID   string   `json:"session_id,omitempty"`
	StartTime   *string  `json:"start_time,omitempty"`
	EndTime     *string  `json:"end_time,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Search      string   `json:"search,omitempty"`
	MinDuration *int64   `json:"min_duration,omitempty"`
	MaxDuration *int64   `json:"max_duration,omitempty"`
	HasError    *bool    `json:"has_error,omitempty"`
	PaginationRequest
}

// StatsRequest represents statistics request
type StatsRequest struct {
	TimeRange   string            `json:"time_range" validate:"required,oneof=1h 6h 12h 24h 7d 30d 90d 1y"`
	Granularity string            `json:"granularity,omitempty" validate:"omitempty,oneof=minute hour day week month"`
	GroupBy     []string          `json:"group_by,omitempty"`
	Filters     map[string]string `json:"filters,omitempty"`
	Metrics     []string          `json:"metrics,omitempty"`
}

// TimeSeriesData represents time series data point
type TimeSeriesData struct {
	Timestamp string                 `json:"timestamp"`
	Values    map[string]interface{} `json:"values"`
	Labels    map[string]string      `json:"labels,omitempty"`
}

// DashboardData represents dashboard data
type DashboardData struct {
	Summary   map[string]interface{} `json:"summary"`
	Charts    []ChartData            `json:"charts"`
	Tables    []TableData            `json:"tables"`
	Alerts    []AlertData            `json:"alerts"`
	UpdatedAt string                 `json:"updated_at"`
}

// ChartData represents chart data
type ChartData struct {
	Type   string                 `json:"type"`
	Title  string                 `json:"title"`
	Data   []TimeSeriesData       `json:"data"`
	Config map[string]interface{} `json:"config,omitempty"`
}

// TableData represents table data
type TableData struct {
	Title   string                 `json:"title"`
	Headers []string               `json:"headers"`
	Rows    [][]interface{}        `json:"rows"`
	Config  map[string]interface{} `json:"config,omitempty"`
}

// AlertData represents alert data
type AlertData struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Severity string                 `json:"severity"`
	Title    string                 `json:"title"`
	Message  string                 `json:"message"`
	Status   string                 `json:"status"`
	Created  string                 `json:"created"`
	Data     map[string]interface{} `json:"data,omitempty"`
}

// ValidationErrorResponse represents validation error response
type ValidationErrorResponse struct {
	Field   string `json:"field"`
	Value   string `json:"value"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// ToRepoFilter converts DTO pagination to repository filter
func (p *PaginationRequest) ToRepoFilter() repositories.PaginationParams {
	page := p.Page
	if page < 1 {
		page = 1
	}
	pageSize := p.PageSize
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	return repositories.NewPaginationParams(page, pageSize)
}
