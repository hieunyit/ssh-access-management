package entities

import (
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"
)

type AuditLog struct {
	ID         uint          `json:"id" gorm:"primaryKey"`
	UserID     *uint         `json:"user_id" gorm:"index"`
	Action     AuditAction   `json:"action" gorm:"not null;type:varchar(50);index"`
	Resource   AuditResource `json:"resource" gorm:"not null;type:varchar(50);index"`
	ResourceID *uint         `json:"resource_id" gorm:"index"`
	Status     AuditStatus   `json:"status" gorm:"not null;type:varchar(20);index"`
	Method     string        `json:"method" gorm:"size:10"`            // HTTP method or protocol
	Endpoint   string        `json:"endpoint" gorm:"size:255"`         // API endpoint or SSH command
	IPAddress  string        `json:"ip_address" gorm:"size:45;index"`  // Client IP address
	UserAgent  string        `json:"user_agent" gorm:"size:500"`       // User agent string
	SessionID  string        `json:"session_id" gorm:"size:100;index"` // Session ID
	RequestID  string        `json:"request_id" gorm:"size:100;index"` // Request correlation ID
	Duration   int64         `json:"duration"`                         // Request duration in milliseconds
	Details    AuditDetails  `json:"details" gorm:"type:jsonb"`        // Additional details
	Changes    AuditChanges  `json:"changes" gorm:"type:jsonb"`        // Before/after changes
	Metadata   AuditMetadata `json:"metadata" gorm:"type:jsonb"`       // Additional metadata
	Tags       StringArray   `json:"tags" gorm:"type:jsonb"`           // Tags for categorization
	Severity   AuditSeverity `json:"severity" gorm:"not null;type:varchar(20);default:'info'"`
	User       *User         `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Timestamp  time.Time     `json:"timestamp" gorm:"not null;index"`
	CreatedAt  time.Time     `json:"created_at"`
}

// AuditAction represents audit action types
type AuditAction string

const (
	// User actions
	ActionUserCreate         AuditAction = "user.create"
	ActionUserUpdate         AuditAction = "user.update"
	ActionUserDelete         AuditAction = "user.delete"
	ActionUserLogin          AuditAction = "user.login"
	ActionUserLogout         AuditAction = "user.logout"
	ActionUserLockout        AuditAction = "user.lockout"
	ActionUserPasswordChange AuditAction = "user.password_change"

	// Server actions
	ActionServerCreate     AuditAction = "server.create"
	ActionServerUpdate     AuditAction = "server.update"
	ActionServerDelete     AuditAction = "server.delete"
	ActionServerAccess     AuditAction = "server.access"
	ActionServerDisconnect AuditAction = "server.disconnect"

	// Group actions
	ActionGroupCreate     AuditAction = "group.create"
	ActionGroupUpdate     AuditAction = "group.update"
	ActionGroupDelete     AuditAction = "group.delete"
	ActionGroupAddUser    AuditAction = "group.add_user"
	ActionGroupRemoveUser AuditAction = "group.remove_user"

	// Project actions
	ActionProjectCreate     AuditAction = "project.create"
	ActionProjectUpdate     AuditAction = "project.update"
	ActionProjectDelete     AuditAction = "project.delete"
	ActionProjectAddUser    AuditAction = "project.add_user"
	ActionProjectRemoveUser AuditAction = "project.remove_user"

	// Access actions
	ActionAccessGrant   AuditAction = "access.grant"
	ActionAccessRevoke  AuditAction = "access.revoke"
	ActionAccessRequest AuditAction = "access.request"
	ActionAccessApprove AuditAction = "access.approve"
	ActionAccessReject  AuditAction = "access.reject"

	// SSH actions
	ActionSSHConnect      AuditAction = "ssh.connect"
	ActionSSHDisconnect   AuditAction = "ssh.disconnect"
	ActionSSHCommand      AuditAction = "ssh.command"
	ActionSSHFileTransfer AuditAction = "ssh.file_transfer"
	ActionSSHPortForward  AuditAction = "ssh.port_forward"

	// API actions
	ActionAPIRequest AuditAction = "api.request"
	ActionAPIError   AuditAction = "api.error"

	// System actions
	ActionSystemStartup  AuditAction = "system.startup"
	ActionSystemShutdown AuditAction = "system.shutdown"
	ActionSystemBackup   AuditAction = "system.backup"
	ActionSystemRestore  AuditAction = "system.restore"
)

// AuditResource represents audit resource types
type AuditResource string

const (
	ResourceUser    AuditResource = "user"
	ResourceServer  AuditResource = "server"
	ResourceGroup   AuditResource = "group"
	ResourceProject AuditResource = "project"
	ResourceAccess  AuditResource = "access"
	ResourceSSH     AuditResource = "ssh"
	ResourceAPI     AuditResource = "api"
	ResourceSystem  AuditResource = "system"
)

// AuditStatus represents audit status types
type AuditStatus string

const (
	StatusSuccess AuditStatus = "success"
	StatusFailure AuditStatus = "failure"
	StatusWarning AuditStatus = "warning"
	StatusInfo    AuditStatus = "info"
)

// AuditSeverity represents audit severity levels
type AuditSeverity string

const (
	SeverityLow      AuditSeverity = "low"
	SeverityInfo     AuditSeverity = "info"
	SeverityWarning  AuditSeverity = "warning"
	SeverityHigh     AuditSeverity = "high"
	SeverityCritical AuditSeverity = "critical"
)

// AuditDetails represents detailed audit information
type AuditDetails struct {
	Description  string                 `json:"description"`
	ErrorMessage string                 `json:"error_message,omitempty"`
	ErrorCode    string                 `json:"error_code,omitempty"`
	StackTrace   string                 `json:"stack_trace,omitempty"`
	RequestBody  map[string]interface{} `json:"request_body,omitempty"`
	ResponseBody map[string]interface{} `json:"response_body,omitempty"`
	QueryParams  map[string]string      `json:"query_params,omitempty"`
	Headers      map[string]string      `json:"headers,omitempty"`
	Environment  string                 `json:"environment,omitempty"`
	Command      string                 `json:"command,omitempty"`     // SSH command executed
	ExitCode     *int                   `json:"exit_code,omitempty"`   // Command exit code
	FileSize     *int64                 `json:"file_size,omitempty"`   // File transfer size
	FilePath     string                 `json:"file_path,omitempty"`   // File path
	LocalPort    *int                   `json:"local_port,omitempty"`  // Port forwarding local port
	RemotePort   *int                   `json:"remote_port,omitempty"` // Port forwarding remote port
	RemoteHost   string                 `json:"remote_host,omitempty"` // Port forwarding remote host
}

// AuditChanges represents before/after changes
type AuditChanges struct {
	Before map[string]interface{} `json:"before,omitempty"`
	After  map[string]interface{} `json:"after,omitempty"`
	Fields []string               `json:"fields,omitempty"` // List of changed fields
}

// AuditMetadata represents additional metadata
type AuditMetadata struct {
	ClientVersion   string            `json:"client_version,omitempty"`
	ServerVersion   string            `json:"server_version,omitempty"`
	Platform        string            `json:"platform,omitempty"`
	Location        string            `json:"location,omitempty"` // Geographic location
	Organization    string            `json:"organization,omitempty"`
	Department      string            `json:"department,omitempty"`
	CostCenter      string            `json:"cost_center,omitempty"`
	Project         string            `json:"project,omitempty"`
	Environment     string            `json:"environment,omitempty"`
	ComplianceFlags []string          `json:"compliance_flags,omitempty"` // Compliance requirements
	RiskLevel       string            `json:"risk_level,omitempty"`
	CustomFields    map[string]string `json:"custom_fields,omitempty"`
}

// TableName sets the table name for AuditLog
func (AuditLog) TableName() string {
	return "audit_logs"
}

// BeforeCreate hook to set default values
func (al *AuditLog) BeforeCreate(tx *gorm.DB) error {
	if al.Severity == "" {
		al.Severity = SeverityInfo
	}
	if al.Timestamp.IsZero() {
		al.Timestamp = time.Now()
	}
	return nil
}

// IsSecurityEvent checks if audit log is a security-related event
func (al *AuditLog) IsSecurityEvent() bool {
	securityActions := []AuditAction{
		ActionUserLogin,
		ActionUserLogout,
		ActionUserLockout,
		ActionUserPasswordChange,
		ActionAccessGrant,
		ActionAccessRevoke,
		ActionSSHConnect,
		ActionSSHDisconnect,
		ActionSSHCommand,
	}

	for _, action := range securityActions {
		if al.Action == action {
			return true
		}
	}
	return false
}

// IsFailure checks if audit log represents a failure
func (al *AuditLog) IsFailure() bool {
	return al.Status == StatusFailure
}

// IsHighSeverity checks if audit log is high severity
func (al *AuditLog) IsHighSeverity() bool {
	return al.Severity == SeverityHigh || al.Severity == SeverityCritical
}

// GetResourceInfo returns resource information as string
func (al *AuditLog) GetResourceInfo() string {
	if al.ResourceID != nil {
		return fmt.Sprintf("%s:%d", al.Resource, *al.ResourceID)
	}
	return string(al.Resource)
}

// AddTag adds a tag to the audit log
func (al *AuditLog) AddTag(tag string) {
	for _, t := range al.Tags {
		if t == tag {
			return // Tag already exists
		}
	}
	al.Tags = append(al.Tags, tag)
}

// HasTag checks if audit log has specific tag
func (al *AuditLog) HasTag(tag string) bool {
	for _, t := range al.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// SetError sets error details in the audit log
func (al *AuditLog) SetError(err error, code string) {
	al.Status = StatusFailure
	al.Severity = SeverityHigh
	al.Details.ErrorMessage = err.Error()
	al.Details.ErrorCode = code
}

// SetCommand sets SSH command details
func (al *AuditLog) SetCommand(command string, exitCode int) {
	al.Details.Command = command
	al.Details.ExitCode = &exitCode
}

// SetFileTransfer sets file transfer details
func (al *AuditLog) SetFileTransfer(filePath string, fileSize int64) {
	al.Details.FilePath = filePath
	al.Details.FileSize = &fileSize
}

// SetPortForward sets port forwarding details
func (al *AuditLog) SetPortForward(localPort, remotePort int, remoteHost string) {
	al.Details.LocalPort = &localPort
	al.Details.RemotePort = &remotePort
	al.Details.RemoteHost = remoteHost
}

// ToJSON converts audit log to JSON string
func (al *AuditLog) ToJSON() (string, error) {
	data, err := json.Marshal(al)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// CreateAuditLog creates a new audit log entry
func CreateAuditLog(action AuditAction, resource AuditResource, userID *uint) *AuditLog {
	return &AuditLog{
		UserID:    userID,
		Action:    action,
		Resource:  resource,
		Status:    StatusInfo,
		Severity:  SeverityInfo,
		Timestamp: time.Now(),
		Details:   AuditDetails{},
		Changes:   AuditChanges{},
		Metadata:  AuditMetadata{},
		Tags:      StringArray{},
	}
}

// CreateSecurityAuditLog creates a security-related audit log
func CreateSecurityAuditLog(action AuditAction, userID *uint, ip, userAgent string) *AuditLog {
	log := CreateAuditLog(action, ResourceUser, userID)
	log.IPAddress = ip
	log.UserAgent = userAgent
	log.Severity = SeverityHigh
	log.AddTag("security")
	return log
}

// CreateSSHAuditLog creates an SSH-related audit log
func CreateSSHAuditLog(action AuditAction, userID *uint, serverID uint, ip string) *AuditLog {
	log := CreateAuditLog(action, ResourceSSH, userID)
	log.ResourceID = &serverID
	log.IPAddress = ip
	log.AddTag("ssh")
	return log
}

// CreateAPIAuditLog creates an API-related audit log
func CreateAPIAuditLog(method, endpoint string, userID *uint, ip, userAgent string) *AuditLog {
	log := CreateAuditLog(ActionAPIRequest, ResourceAPI, userID)
	log.Method = method
	log.Endpoint = endpoint
	log.IPAddress = ip
	log.UserAgent = userAgent
	log.AddTag("api")
	return log
}
