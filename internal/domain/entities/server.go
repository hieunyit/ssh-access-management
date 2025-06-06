package entities

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"
)

type Server struct {
	ID          uint           `json:"id" gorm:"primaryKey"`
	Name        string         `json:"name" gorm:"uniqueIndex;not null;size:100"`
	IP          string         `json:"ip" gorm:"not null;size:45;index"` // Support both IPv4 and IPv6
	Hostname    string         `json:"hostname" gorm:"size:255"`
	Description string         `json:"description" gorm:"type:text"`
	Environment string         `json:"environment" gorm:"not null;size:50;index"`       // production, staging, dev, test
	Platform    Platform       `json:"platform" gorm:"not null;type:varchar(20);index"` // vsphere, aws, azure
	OS          string         `json:"os" gorm:"not null;size:100"`
	OSVersion   string         `json:"os_version" gorm:"size:50"`
	Tags        StringArray    `json:"tags" gorm:"type:jsonb"`
	Status      ServerStatus   `json:"status" gorm:"not null;type:varchar(20);default:'active';index"`
	SSHPort     int            `json:"ssh_port" gorm:"default:22"`
	SSHUser     string         `json:"ssh_user" gorm:"size:50;default:'root'"` // Default SSH user for automation
	Region      string         `json:"region" gorm:"size:50"`                  // Cloud region or datacenter
	Groups      []Group        `json:"groups" gorm:"many2many:server_groups;"`
	Projects    []Project      `json:"projects" gorm:"many2many:server_projects;"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`
}

// Platform represents server platform types
type Platform string

const (
	PlatformVSphere Platform = "vsphere"
	PlatformAWS     Platform = "aws"
	PlatformAzure   Platform = "azure"
)

// ServerStatus represents server status types
type ServerStatus string

const (
	ServerStatusActive   ServerStatus = "active"
	ServerStatusInactive ServerStatus = "inactive"
	ServerStatusBanned   ServerStatus = "banned"
)

// Environment represents server environment types
type Environment string

const (
	EnvironmentProduction Environment = "production"
	EnvironmentStaging    Environment = "staging"
	EnvironmentDev        Environment = "dev"
	EnvironmentTest       Environment = "test"
)

// StringArray custom type for PostgreSQL JSONB array
type StringArray []string

// Value implements driver.Valuer interface for database storage
func (s StringArray) Value() (driver.Value, error) {
	if len(s) == 0 {
		return "[]", nil
	}
	return json.Marshal(s)
}

// Scan implements sql.Scanner interface for database retrieval
func (s *StringArray) Scan(value interface{}) error {
	if value == nil {
		*s = StringArray{}
		return nil
	}

	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, s)
	case string:
		return json.Unmarshal([]byte(v), s)
	default:
		return fmt.Errorf("cannot scan %T into StringArray", value)
	}
}

// TableName sets the table name for Server
func (Server) TableName() string {
	return "servers"
}

// BeforeCreate hook to set default values
func (s *Server) BeforeCreate(tx *gorm.DB) error {
	if s.Status == "" {
		s.Status = ServerStatusActive
	}
	if s.SSHPort == 0 {
		s.SSHPort = 22
	}
	if s.SSHUser == "" {
		s.SSHUser = "root"
	}
	return nil
}

// IsActive checks if server is active
func (s *Server) IsActive() bool {
	return s.Status == ServerStatusActive
}

// IsCloud checks if server is in cloud platform
func (s *Server) IsCloud() bool {
	return s.Platform == PlatformAWS || s.Platform == PlatformAzure
}

// IsOnPremise checks if server is on-premise
func (s *Server) IsOnPremise() bool {
	return s.Platform == PlatformVSphere
}

// HasTag checks if server has specific tag
func (s *Server) HasTag(tag string) bool {
	for _, t := range s.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// AddTag adds a tag to server if not exists
func (s *Server) AddTag(tag string) {
	if !s.HasTag(tag) {
		s.Tags = append(s.Tags, tag)
	}
}

// RemoveTag removes a tag from server
func (s *Server) RemoveTag(tag string) {
	for i, t := range s.Tags {
		if t == tag {
			s.Tags = append(s.Tags[:i], s.Tags[i+1:]...)
			break
		}
	}
}

// GetSSHAddress returns the SSH connection address
func (s *Server) GetSSHAddress() string {
	return fmt.Sprintf("%s:%d", s.IP, s.SSHPort)
}

// IsProduction checks if server is in production environment
func (s *Server) IsProduction() bool {
	return s.Environment == string(EnvironmentProduction)
}

// GetPlatformConfig returns platform-specific configuration
func (s *Server) GetPlatformConfig() map[string]interface{} {
	config := make(map[string]interface{})

	switch s.Platform {
	case PlatformAWS:
		config["type"] = "aws"
		config["region"] = s.Region
		config["ssh_user"] = s.SSHUser
	case PlatformAzure:
		config["type"] = "azure"
		config["region"] = s.Region
		config["ssh_user"] = s.SSHUser
	case PlatformVSphere:
		config["type"] = "vsphere"
		config["datacenter"] = s.Region
		config["ssh_user"] = s.SSHUser
	}

	return config
}

// ValidateServer validates server data
func (s *Server) ValidateServer() error {
	if s.Name == "" {
		return ErrInvalidServerName
	}
	if s.IP == "" {
		return ErrInvalidServerIP
	}
	if s.Environment == "" {
		return ErrInvalidServerEnvironment
	}
	if s.Platform == "" {
		return ErrInvalidServerPlatform
	}
	if s.OS == "" {
		return ErrInvalidServerOS
	}

	// Validate platform
	validPlatforms := []Platform{PlatformVSphere, PlatformAWS, PlatformAzure}
	isValidPlatform := false
	for _, platform := range validPlatforms {
		if s.Platform == platform {
			isValidPlatform = true
			break
		}
	}
	if !isValidPlatform {
		return ErrInvalidServerPlatform
	}

	// Validate environment
	validEnvironments := []Environment{EnvironmentProduction, EnvironmentStaging, EnvironmentDev, EnvironmentTest}
	isValidEnvironment := false
	for _, env := range validEnvironments {
		if s.Environment == string(env) {
			isValidEnvironment = true
			break
		}
	}
	if !isValidEnvironment {
		return ErrInvalidServerEnvironment
	}

	return nil
}
