package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Environment string   `mapstructure:"ENVIRONMENT"`
	Server      Server   `mapstructure:",squash"`
	Database    Database `mapstructure:",squash"`
	JWT         JWT      `mapstructure:",squash"`
	LogLevel    string   `mapstructure:"LOG_LEVEL"`
}

type Server struct {
	Port string `mapstructure:"SERVER_PORT"`
}

type Database struct {
	Host     string `mapstructure:"DB_HOST"`
	Port     string `mapstructure:"DB_PORT"`
	Name     string `mapstructure:"DB_NAME"`
	User     string `mapstructure:"DB_USER"`
	Password string `mapstructure:"DB_PASSWORD"`
	SSLMode  string `mapstructure:"DB_SSLMODE"`
	URL      string `mapstructure:"DATABASE_URL"`
}

type JWT struct {
	Secret          string `mapstructure:"JWT_SECRET"`
	ExpirationHours int    `mapstructure:"JWT_EXPIRATION_HOURS"`
	RefreshHours    int    `mapstructure:"JWT_REFRESH_HOURS"`
	Issuer          string `mapstructure:"JWT_ISSUER"`
}

func Load() (*Config, error) {
	viper.SetConfigName(".env")
	viper.SetConfigType("env")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./")
	viper.AutomaticEnv()

	// Set default values
	setDefaults()

	// Allow viper to read from environment variables
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Read config file if exists
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Build database URL if not provided
	if config.Database.URL == "" {
		config.Database.URL = fmt.Sprintf(
			"postgres://%s:%s@%s:%s/%s?sslmode=%s",
			config.Database.User,
			config.Database.Password,
			config.Database.Host,
			config.Database.Port,
			config.Database.Name,
			config.Database.SSLMode,
		)
	}

	if err := validate(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}

func setDefaults() {
	// Server defaults
	viper.SetDefault("ENVIRONMENT", "development")
	viper.SetDefault("SERVER_PORT", "8080")
	viper.SetDefault("LOG_LEVEL", "info")

	// Database defaults
	viper.SetDefault("DB_HOST", "localhost")
	viper.SetDefault("DB_PORT", "5432")
	viper.SetDefault("DB_NAME", "ssh_access_management")
	viper.SetDefault("DB_USER", "postgres")
	viper.SetDefault("DB_PASSWORD", "postgres")
	viper.SetDefault("DB_SSLMODE", "disable")

	// JWT defaults
	viper.SetDefault("JWT_SECRET", "your-super-secret-key-change-in-production")
	viper.SetDefault("JWT_EXPIRATION_HOURS", 24)
	viper.SetDefault("JWT_REFRESH_HOURS", 168) // 7 days
	viper.SetDefault("JWT_ISSUER", "ssh-access-management")
}

func validate(config *Config) error {
	if config.Server.Port == "" {
		return fmt.Errorf("server port is required")
	}

	if config.Database.Host == "" {
		return fmt.Errorf("database host is required")
	}

	if config.Database.Name == "" {
		return fmt.Errorf("database name is required")
	}

	if config.Database.User == "" {
		return fmt.Errorf("database user is required")
	}

	if config.JWT.Secret == "" {
		return fmt.Errorf("JWT secret is required")
	}

	if config.Environment == "production" && config.JWT.Secret == "your-super-secret-key-change-in-production" {
		return fmt.Errorf("JWT secret must be changed in production")
	}

	return nil
}
