package entities

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID          uint           `json:"id" gorm:"primaryKey"`
	Username    string         `json:"username" gorm:"uniqueIndex;not null;size:100"`
	Email       string         `json:"email" gorm:"uniqueIndex;not null;size:255"`
	FullName    string         `json:"full_name" gorm:"not null;size:255"`
	Password    string         `json:"-" gorm:"not null;size:255"`
	Department  string         `json:"department" gorm:"size:100"`
	Role        string         `json:"role" gorm:"not null;size:50;default:'user'"`     // admin, user, readonly
	Status      string         `json:"status" gorm:"not null;size:20;default:'active'"` // active, inactive, banned
	LastLoginAt *time.Time     `json:"last_login_at"`
	SSHKeys     []SSHKey       `json:"ssh_keys" gorm:"foreignKey:UserID"`
	Groups      []Group        `json:"groups" gorm:"many2many:user_groups;"`
	Projects    []Project      `json:"projects" gorm:"many2many:user_projects;"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`
}

type SSHKey struct {
	ID          uint           `json:"id" gorm:"primaryKey"`
	UserID      uint           `json:"user_id" gorm:"not null;index"`
	Name        string         `json:"name" gorm:"not null;size:100"`
	PublicKey   string         `json:"public_key" gorm:"not null;type:text"`
	Fingerprint string         `json:"fingerprint" gorm:"not null;size:255;uniqueIndex"`
	KeyType     string         `json:"key_type" gorm:"not null;size:20"` // rsa, ed25519, ecdsa
	BitLength   int            `json:"bit_length"`
	Comment     string         `json:"comment" gorm:"size:255"`
	IsActive    bool           `json:"is_active" gorm:"default:true"`
	ExpiresAt   *time.Time     `json:"expires_at"`
	User        User           `json:"user" gorm:"foreignKey:UserID"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`
}

// UserRole represents user role types
type UserRole string

const (
	RoleAdmin    UserRole = "admin"
	RoleUser     UserRole = "user"
	RoleReadonly UserRole = "readonly"
)

// UserStatus represents user status types
type UserStatus string

const (
	StatusActive   UserStatus = "active"
	StatusInactive UserStatus = "inactive"
	StatusBanned   UserStatus = "banned"
)

// TableName sets the table name for User
func (User) TableName() string {
	return "users"
}

// TableName sets the table name for SSHKey
func (SSHKey) TableName() string {
	return "ssh_keys"
}

// BeforeCreate hook to set default values
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.Role == "" {
		u.Role = string(RoleUser)
	}
	if u.Status == "" {
		u.Status = string(StatusActive)
	}
	return nil
}

// IsAdmin checks if user has admin role
func (u *User) IsAdmin() bool {
	return u.Role == string(RoleAdmin)
}

// IsActive checks if user is active
func (u *User) IsActive() bool {
	return u.Status == string(StatusActive)
}

// CanManageUsers checks if user can manage other users
func (u *User) CanManageUsers() bool {
	return u.Role == string(RoleAdmin)
}

// CanManageServers checks if user can manage servers
func (u *User) CanManageServers() bool {
	return u.Role == string(RoleAdmin) || u.Role == string(RoleUser)
}

// CanGrantAccess checks if user can grant access to servers
func (u *User) CanGrantAccess() bool {
	return u.Role == string(RoleAdmin)
}

// GetActiveSSHKeys returns only active SSH keys
func (u *User) GetActiveSSHKeys() []SSHKey {
	var activeKeys []SSHKey
	for _, key := range u.SSHKeys {
		if key.IsActive && (key.ExpiresAt == nil || key.ExpiresAt.After(time.Now())) {
			activeKeys = append(activeKeys, key)
		}
	}
	return activeKeys
}

// ValidateSSHKey validates SSH key before creation/update
func (s *SSHKey) ValidateSSHKey() error {
	if s.Name == "" {
		return ErrInvalidSSHKeyName
	}
	if s.PublicKey == "" {
		return ErrInvalidSSHKeyContent
	}
	if s.KeyType == "" {
		return ErrInvalidSSHKeyType
	}
	return nil
}

// IsExpired checks if SSH key is expired
func (s *SSHKey) IsExpired() bool {
	return s.ExpiresAt != nil && s.ExpiresAt.Before(time.Now())
}
