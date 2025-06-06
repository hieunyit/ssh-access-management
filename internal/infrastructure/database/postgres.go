package database

import (
	"fmt"
	"log"
	"time"

	"ssh-access-management/internal/config"
	"ssh-access-management/internal/domain/entities"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var db *gorm.DB

// NewPostgresConnection creates a new PostgreSQL database connection
func NewPostgresConnection(cfg config.Database) (*gorm.DB, error) {
	var err error

	// Configure GORM logger
	gormLogger := logger.Default
	if cfg.Host != "localhost" {
		gormLogger = logger.Default.LogMode(logger.Silent)
	} else {
		gormLogger = logger.Default.LogMode(logger.Info)
	}

	// Open database connection
	db, err = gorm.Open(postgres.Open(cfg.URL), &gorm.Config{
		Logger: gormLogger,
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Get underlying sql.DB to configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	// Configure connection pool
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// Test connection
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Auto-migrate schemas
	if err := autoMigrate(db); err != nil {
		return nil, fmt.Errorf("failed to auto-migrate: %w", err)
	}

	log.Println("Successfully connected to PostgreSQL database")
	return db, nil
}

// GetDB returns the database instance
func GetDB() *gorm.DB {
	return db
}

// Close closes the database connection
func Close() error {
	if db != nil {
		sqlDB, err := db.DB()
		if err != nil {
			return fmt.Errorf("failed to get underlying sql.DB: %w", err)
		}
		return sqlDB.Close()
	}
	return nil
}

// autoMigrate performs automatic migration of database schemas
func autoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&entities.User{},
		&entities.SSHKey{},
		&entities.Server{},
		&entities.Group{},
		&entities.Project{},
		&entities.AccessGrant{},
		&entities.AccessRequest{},
		&entities.AuditLog{},
	)
}

// CreateIndexes creates additional indexes for performance optimization
func CreateIndexes(db *gorm.DB) error {
	// User indexes
	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_users_username_email ON users(username, email)").Error; err != nil {
		return err
	}
	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_users_status_role ON users(status, role)").Error; err != nil {
		return err
	}

	// Server indexes
	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_servers_platform_environment ON servers(platform, environment)").Error; err != nil {
		return err
	}
	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_servers_status_platform ON servers(status, platform)").Error; err != nil {
		return err
	}
	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_servers_tags ON servers USING GIN(tags)").Error; err != nil {
		return err
	}

	// Access grant indexes
	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_access_grants_user_server ON access_grants(user_id, server_id)").Error; err != nil {
		return err
	}
	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_access_grants_status_expires ON access_grants(status, expires_at)").Error; err != nil {
		return err
	}
	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_access_grants_granted_at ON access_grants(granted_at)").Error; err != nil {
		return err
	}

	// Audit log indexes
	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_audit_logs_user_action ON audit_logs(user_id, action)").Error; err != nil {
		return err
	}
	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_action ON audit_logs(resource, action)").Error; err != nil {
		return err
	}
	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp_severity ON audit_logs(timestamp, severity)").Error; err != nil {
		return err
	}
	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_audit_logs_session_id ON audit_logs(session_id)").Error; err != nil {
		return err
	}
	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_audit_logs_ip_address ON audit_logs(ip_address)").Error; err != nil {
		return err
	}

	// SSH key indexes
	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_ssh_keys_user_active ON ssh_keys(user_id, is_active)").Error; err != nil {
		return err
	}
	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_ssh_keys_expires_at ON ssh_keys(expires_at)").Error; err != nil {
		return err
	}

	return nil
}

// HealthCheck performs a health check on the database connection
func HealthCheck() error {
	if db == nil {
		return fmt.Errorf("database connection is nil")
	}

	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	if err := sqlDB.Ping(); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	return nil
}

// GetConnectionStats returns database connection statistics
func GetConnectionStats() map[string]interface{} {
	if db == nil {
		return map[string]interface{}{"error": "database connection is nil"}
	}

	sqlDB, err := db.DB()
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}

	stats := sqlDB.Stats()
	return map[string]interface{}{
		"max_open_connections": stats.MaxOpenConnections,
		"open_connections":     stats.OpenConnections,
		"in_use":               stats.InUse,
		"idle":                 stats.Idle,
		"wait_count":           stats.WaitCount,
		"wait_duration":        stats.WaitDuration.String(),
		"max_idle_closed":      stats.MaxIdleClosed,
		"max_idle_time_closed": stats.MaxIdleTimeClosed,
		"max_lifetime_closed":  stats.MaxLifetimeClosed,
	}
}

// BeginTransaction starts a new database transaction
func BeginTransaction() *gorm.DB {
	return db.Begin()
}

// WithTransaction executes a function within a database transaction
func WithTransaction(fn func(*gorm.DB) error) error {
	tx := db.Begin()
	if tx.Error != nil {
		return tx.Error
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

// CreateTestDatabase creates a test database for testing purposes
func CreateTestDatabase() (*gorm.DB, error) {
	// Use in-memory SQLite for testing
	testDB, err := gorm.Open(postgres.Open("postgres://test:test@localhost/test_ssh_access?sslmode=disable"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create test database: %w", err)
	}

	// Auto-migrate for tests
	if err := autoMigrate(testDB); err != nil {
		return nil, fmt.Errorf("failed to migrate test database: %w", err)
	}

	return testDB, nil
}

// SeedDatabase seeds the database with initial data
func SeedDatabase(db *gorm.DB) error {
	// Create default admin user
	adminUser := &entities.User{
		Username: "admin",
		Email:    "admin@example.com",
		FullName: "System Administrator",
		Password: "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi", // password
		Role:     string(entities.RoleAdmin),
		Status:   string(entities.StatusActive),
	}

	if err := db.FirstOrCreate(adminUser, entities.User{Username: "admin"}).Error; err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	// Create default environments
	environments := []string{"production", "staging", "development", "test"}
	for _, env := range environments {
		// Create environment-specific groups if they don't exist
		group := &entities.Group{
			Name:        fmt.Sprintf("%s-servers", env),
			Description: fmt.Sprintf("Servers in %s environment", env),
			Type:        entities.GroupTypeDepartment,
			IsActive:    true,
		}
		if err := db.FirstOrCreate(group, entities.Group{Name: group.Name}).Error; err != nil {
			return fmt.Errorf("failed to create group for environment %s: %w", env, err)
		}
	}

	// Create default project
	defaultProject := &entities.Project{
		Name:        "Default Project",
		Code:        "DEFAULT",
		Description: "Default project for unassigned resources",
		Status:      entities.ProjectStatusActive,
		Priority:    entities.ProjectPriorityMedium,
		OwnerID:     adminUser.ID,
	}

	if err := db.FirstOrCreate(defaultProject, entities.Project{Code: "DEFAULT"}).Error; err != nil {
		return fmt.Errorf("failed to create default project: %w", err)
	}

	log.Println("Database seeded successfully")
	return nil
}

// GetDatabaseVersion returns the PostgreSQL version
func GetDatabaseVersion() (string, error) {
	var version string
	if err := db.Raw("SELECT version()").Scan(&version).Error; err != nil {
		return "", fmt.Errorf("failed to get database version: %w", err)
	}
	return version, nil
}

// OptimizeDatabase performs database optimization tasks
func OptimizeDatabase() error {
	// Analyze tables for better query planning
	tables := []string{"users", "servers", "groups", "projects", "access_grants", "audit_logs", "ssh_keys"}

	for _, table := range tables {
		if err := db.Exec(fmt.Sprintf("ANALYZE %s", table)).Error; err != nil {
			return fmt.Errorf("failed to analyze table %s: %w", table, err)
		}
	}

	// Vacuum tables to reclaim space
	for _, table := range tables {
		if err := db.Exec(fmt.Sprintf("VACUUM %s", table)).Error; err != nil {
			return fmt.Errorf("failed to vacuum table %s: %w", table, err)
		}
	}

	log.Println("Database optimization completed")
	return nil
}
