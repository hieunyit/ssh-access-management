package entities

import (
	"time"

	"gorm.io/gorm"
)

type AccessGrant struct {
	ID            uint             `json:"id" gorm:"primaryKey"`
	UserID        *uint            `json:"user_id" gorm:"index"`
	GroupID       *uint            `json:"group_id" gorm:"index"`
	ProjectID     *uint            `json:"project_id" gorm:"index"`
	ServerID      uint             `json:"server_id" gorm:"not null;index"`
	Role          AccessRole       `json:"role" gorm:"not null;type:varchar(20);default:'readonly'"`
	Status        AccessStatus     `json:"status" gorm:"not null;type:varchar(20);default:'active'"`
	Reason        string           `json:"reason" gorm:"type:text"`
	GrantedBy     uint             `json:"granted_by" gorm:"not null;index"`
	GrantedAt     time.Time        `json:"granted_at" gorm:"not null"`
	ExpiresAt     *time.Time       `json:"expires_at" gorm:"index"`
	RevokedBy     *uint            `json:"revoked_by" gorm:"index"`
	RevokedAt     *time.Time       `json:"revoked_at"`
	LastUsedAt    *time.Time       `json:"last_used_at"`
	UsageCount    int              `json:"usage_count" gorm:"default:0"`
	Conditions    AccessConditions `json:"conditions" gorm:"type:jsonb"`
	User          *User            `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Group         *Group           `json:"group,omitempty" gorm:"foreignKey:GroupID"`
	Project       *Project         `json:"project,omitempty" gorm:"foreignKey:ProjectID"`
	Server        Server           `json:"server" gorm:"foreignKey:ServerID"`
	GrantedByUser User             `json:"granted_by_user" gorm:"foreignKey:GrantedBy"`
	RevokedByUser *User            `json:"revoked_by_user,omitempty" gorm:"foreignKey:RevokedBy"`
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
	DeletedAt     gorm.DeletedAt   `json:"-" gorm:"index"`
}

// AccessRole represents access role types
type AccessRole string

const (
	AccessRoleReadonly AccessRole = "readonly"
	AccessRoleUser     AccessRole = "user"
	AccessRoleAdmin    AccessRole = "admin"
	AccessRoleCustom   AccessRole = "custom"
)

// AccessStatus represents access status types
type AccessStatus string

const (
	AccessStatusActive    AccessStatus = "active"
	AccessStatusInactive  AccessStatus = "inactive"
	AccessStatusRevoked   AccessStatus = "revoked"
	AccessStatusExpired   AccessStatus = "expired"
	AccessStatusSuspended AccessStatus = "suspended"
)

// AccessConditions represents access conditions and constraints
type AccessConditions struct {
	IPWhitelist      []string          `json:"ip_whitelist"`       // Allowed IP addresses/ranges
	TimeRestrictions TimeRestrictions  `json:"time_restrictions"`  // Time-based restrictions
	SessionTimeout   int               `json:"session_timeout"`    // Session timeout in minutes
	MaxSessions      int               `json:"max_sessions"`       // Max concurrent sessions
	AllowedCommands  []string          `json:"allowed_commands"`   // Allowed SSH commands
	DeniedCommands   []string          `json:"denied_commands"`    // Denied SSH commands
	RequireMFA       bool              `json:"require_mfa"`        // Require multi-factor auth
	AllowSCP         bool              `json:"allow_scp"`          // Allow SCP file transfer
	AllowSFTP        bool              `json:"allow_sftp"`         // Allow SFTP file transfer
	AllowPortForward bool              `json:"allow_port_forward"` // Allow port forwarding
	CustomRules      map[string]string `json:"custom_rules"`       // Custom access rules
}

// TimeRestrictions represents time-based access restrictions
type TimeRestrictions struct {
	AllowedDays    []string `json:"allowed_days"`    // Mon, Tue, Wed, Thu, Fri, Sat, Sun
	AllowedHours   []string `json:"allowed_hours"`   // HH:MM-HH:MM format
	Timezone       string   `json:"timezone"`        // Timezone for time checks
	MaxDuration    int      `json:"max_duration"`    // Max session duration in minutes
	CooldownPeriod int      `json:"cooldown_period"` // Cooldown between sessions in minutes
}

// AccessRequest represents access request from users
type AccessRequest struct {
	ID              uint             `json:"id" gorm:"primaryKey"`
	RequesterID     uint             `json:"requester_id" gorm:"not null;index"`
	ServerID        uint             `json:"server_id" gorm:"not null;index"`
	Role            AccessRole       `json:"role" gorm:"not null;type:varchar(20)"`
	Reason          string           `json:"reason" gorm:"not null;type:text"`
	Duration        int              `json:"duration" gorm:"not null"` // Requested duration in hours
	Status          RequestStatus    `json:"status" gorm:"not null;type:varchar(20);default:'pending'"`
	ApprovedBy      *uint            `json:"approved_by" gorm:"index"`
	ApprovedAt      *time.Time       `json:"approved_at"`
	RejectedBy      *uint            `json:"rejected_by" gorm:"index"`
	RejectedAt      *time.Time       `json:"rejected_at"`
	RejectionReason string           `json:"rejection_reason" gorm:"type:text"`
	ExpiresAt       time.Time        `json:"expires_at" gorm:"not null"`
	Conditions      AccessConditions `json:"conditions" gorm:"type:jsonb"`
	Requester       User             `json:"requester" gorm:"foreignKey:RequesterID"`
	Server          Server           `json:"server" gorm:"foreignKey:ServerID"`
	ApprovedByUser  *User            `json:"approved_by_user,omitempty" gorm:"foreignKey:ApprovedBy"`
	RejectedByUser  *User            `json:"rejected_by_user,omitempty" gorm:"foreignKey:RejectedBy"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
	DeletedAt       gorm.DeletedAt   `json:"-" gorm:"index"`
}

// RequestStatus represents access request status
type RequestStatus string

const (
	RequestStatusPending  RequestStatus = "pending"
	RequestStatusApproved RequestStatus = "approved"
	RequestStatusRejected RequestStatus = "rejected"
	RequestStatusExpired  RequestStatus = "expired"
)

// TableName sets the table name for AccessGrant
func (AccessGrant) TableName() string {
	return "access_grants"
}

// TableName sets the table name for AccessRequest
func (AccessRequest) TableName() string {
	return "access_requests"
}

// BeforeCreate hook for AccessGrant
func (ag *AccessGrant) BeforeCreate(tx *gorm.DB) error {
	if ag.Role == "" {
		ag.Role = AccessRoleReadonly
	}
	if ag.Status == "" {
		ag.Status = AccessStatusActive
	}
	if ag.GrantedAt.IsZero() {
		ag.GrantedAt = time.Now()
	}
	return nil
}

// BeforeCreate hook for AccessRequest
func (ar *AccessRequest) BeforeCreate(tx *gorm.DB) error {
	if ar.Status == "" {
		ar.Status = RequestStatusPending
	}
	return nil
}

// IsActive checks if access grant is active
func (ag *AccessGrant) IsActive() bool {
	return ag.Status == AccessStatusActive && !ag.IsExpired()
}

// IsExpired checks if access grant is expired
func (ag *AccessGrant) IsExpired() bool {
	return ag.ExpiresAt != nil && ag.ExpiresAt.Before(time.Now())
}

// IsRevoked checks if access grant is revoked
func (ag *AccessGrant) IsRevoked() bool {
	return ag.Status == AccessStatusRevoked || ag.RevokedAt != nil
}

// CanExecuteCommand checks if command is allowed
func (ag *AccessGrant) CanExecuteCommand(command string) bool {
	// If denied commands list exists and command is in it, deny
	for _, denied := range ag.Conditions.DeniedCommands {
		if command == denied {
			return false
		}
	}

	// If allowed commands list exists, command must be in it
	if len(ag.Conditions.AllowedCommands) > 0 {
		for _, allowed := range ag.Conditions.AllowedCommands {
			if command == allowed {
				return true
			}
		}
		return false
	}

	// If no restrictions, allow
	return true
}

// IsIPAllowed checks if IP address is allowed
func (ag *AccessGrant) IsIPAllowed(ip string) bool {
	if len(ag.Conditions.IPWhitelist) == 0 {
		return true // No restrictions
	}

	for _, allowedIP := range ag.Conditions.IPWhitelist {
		if ip == allowedIP {
			return true
		}
		// TODO: Add CIDR range checking
	}

	return false
}

// IsTimeAllowed checks if current time is within allowed time restrictions
func (ag *AccessGrant) IsTimeAllowed() bool {
	if len(ag.Conditions.TimeRestrictions.AllowedDays) == 0 {
		return true // No restrictions
	}

	now := time.Now()

	// Check allowed days
	currentDay := now.Format("Mon")
	dayAllowed := false
	for _, day := range ag.Conditions.TimeRestrictions.AllowedDays {
		if day == currentDay {
			dayAllowed = true
			break
		}
	}

	if !dayAllowed {
		return false
	}

	// Check allowed hours
	if len(ag.Conditions.TimeRestrictions.AllowedHours) == 0 {
		return true // No hour restrictions
	}

	currentTime := now.Format("15:04")
	for _, timeRange := range ag.Conditions.TimeRestrictions.AllowedHours {
		// TODO: Parse time range and check if current time is within range
		_ = timeRange
		_ = currentTime
	}

	return true
}

// Revoke revokes the access grant
func (ag *AccessGrant) Revoke(revokedBy uint) {
	ag.Status = AccessStatusRevoked
	ag.RevokedBy = &revokedBy
	now := time.Now()
	ag.RevokedAt = &now
}

// UpdateLastUsed updates the last used timestamp and usage count
func (ag *AccessGrant) UpdateLastUsed() {
	now := time.Now()
	ag.LastUsedAt = &now
	ag.UsageCount++
}

// GetGrantType returns the type of grant (user, group, or project)
func (ag *AccessGrant) GetGrantType() string {
	if ag.UserID != nil {
		return "user"
	}
	if ag.GroupID != nil {
		return "group"
	}
	if ag.ProjectID != nil {
		return "project"
	}
	return "unknown"
}

// GetGranteeID returns the ID of the grantee
func (ag *AccessGrant) GetGranteeID() uint {
	if ag.UserID != nil {
		return *ag.UserID
	}
	if ag.GroupID != nil {
		return *ag.GroupID
	}
	if ag.ProjectID != nil {
		return *ag.ProjectID
	}
	return 0
}

// Approve approves the access request
func (ar *AccessRequest) Approve(approvedBy uint) {
	ar.Status = RequestStatusApproved
	ar.ApprovedBy = &approvedBy
	now := time.Now()
	ar.ApprovedAt = &now
}

// Reject rejects the access request
func (ar *AccessRequest) Reject(rejectedBy uint, reason string) {
	ar.Status = RequestStatusRejected
	ar.RejectedBy = &rejectedBy
	ar.RejectionReason = reason
	now := time.Now()
	ar.RejectedAt = &now
}

// IsExpiredRequest checks if access request is expired
func (ar *AccessRequest) IsExpiredRequest() bool {
	return ar.ExpiresAt.Before(time.Now())
}

// IsPending checks if access request is pending
func (ar *AccessRequest) IsPending() bool {
	return ar.Status == RequestStatusPending && !ar.IsExpiredRequest()
}

// ValidateAccessGrant validates access grant data
func (ag *AccessGrant) ValidateAccessGrant() error {
	if ag.ServerID == 0 {
		return ErrInvalidServerID
	}
	if ag.GrantedBy == 0 {
		return ErrInvalidGrantedBy
	}

	// Must have at least one grantee
	if ag.UserID == nil && ag.GroupID == nil && ag.ProjectID == nil {
		return ErrInvalidGrantee
	}

	// Cannot have multiple grantees
	granteeCount := 0
	if ag.UserID != nil {
		granteeCount++
	}
	if ag.GroupID != nil {
		granteeCount++
	}
	if ag.ProjectID != nil {
		granteeCount++
	}
	if granteeCount > 1 {
		return ErrMultipleGrantees
	}

	return nil
}

// ValidateAccessRequest validates access request data
func (ar *AccessRequest) ValidateAccessRequest() error {
	if ar.RequesterID == 0 {
		return ErrInvalidRequesterID
	}
	if ar.ServerID == 0 {
		return ErrInvalidServerID
	}
	if ar.Reason == "" {
		return ErrInvalidReason
	}
	if ar.Duration <= 0 {
		return ErrInvalidDuration
	}

	return nil
}
