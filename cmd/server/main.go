package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ssh-access-management/internal/application/services"
	"ssh-access-management/internal/config"
	"ssh-access-management/internal/delivery/http/handlers"
	"ssh-access-management/internal/delivery/http/middleware"
	"ssh-access-management/internal/delivery/http/routes"
	"ssh-access-management/internal/infrastructure/database"
	"ssh-access-management/internal/infrastructure/repositories"
	"ssh-access-management/internal/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	// Initialize logger
	logger := logger.NewLogger(cfg.LogLevel)

	// Initialize database
	db, err := database.NewPostgresConnection(cfg.Database)
	if err != nil {
		logger.Fatal("Failed to connect to database:", err)
	}

	// Run database migrations
	if err := runMigrations(cfg.Database.URL); err != nil {
		logger.Fatal("Failed to run migrations:", err)
	}

	// Initialize repositories
	userRepo := repositories.NewUserRepository(db)
	serverRepo := repositories.NewServerRepository(db)
	groupRepo := repositories.NewGroupRepository(db)
	projectRepo := repositories.NewProjectRepository(db)
	accessRepo := repositories.NewAccessRepository(db)
	auditRepo := repositories.NewAuditRepository(db)

	// Initialize services
	userService := services.NewUserService(userRepo, auditRepo)
	serverService := services.NewServerService(serverRepo, auditRepo)
	groupService := services.NewGroupService(groupRepo, auditRepo)
	projectService := services.NewProjectService(projectRepo, auditRepo)
	accessService := services.NewAccessService(accessRepo, auditRepo)
	auditService := services.NewAuditService(auditRepo)

	// Initialize handlers
	userHandler := handlers.NewUserHandler(userService)
	serverHandler := handlers.NewServerHandler(serverService)
	groupHandler := handlers.NewGroupHandler(groupService)
	projectHandler := handlers.NewProjectHandler(projectService)
	accessHandler := handlers.NewAccessHandler(accessService)
	auditHandler := handlers.NewAuditHandler(auditService)

	// Setup Gin
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()

	// Global middleware
	r.Use(gin.Recovery())
	r.Use(middleware.Logger(logger))
	r.Use(middleware.CORS())
	r.Use(middleware.RateLimit())

	// Setup routes
	routes.SetupRoutes(r, &routes.Handlers{
		User:    userHandler,
		Server:  serverHandler,
		Group:   groupHandler,
		Project: projectHandler,
		Access:  accessHandler,
		Audit:   auditHandler,
	}, cfg.JWT.Secret)

	// Start server
	srv := &http.Server{
		Addr:    ":" + cfg.Server.Port,
		Handler: r,
	}

	// Graceful shutdown
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start server:", err)
		}
	}()

	logger.Info("Server started on port " + cfg.Server.Port)

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// The context is used to inform the server it has 5 seconds to finish
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown:", err)
	}

	logger.Info("Server exited")
}

func runMigrations(databaseURL string) error {
	driver, err := postgres.WithInstance(database.GetDB().DB(), &postgres.Config{})
	if err != nil {
		return err
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://internal/infrastructure/database/migrations",
		"postgres",
		driver,
	)
	if err != nil {
		return err
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return err
	}

	return nil
}
