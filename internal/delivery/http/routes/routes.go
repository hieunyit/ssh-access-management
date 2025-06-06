package routes

import (
	"ssh-access-management/internal/delivery/http/handlers"
	"ssh-access-management/internal/delivery/http/middleware"

	"github.com/gin-gonic/gin"
)

// Handlers groups all handler dependencies
type Handlers struct {
	User    *handlers.UserHandler
	Server  *handlers.ServerHandler
	Group   *handlers.GroupHandler
	Project *handlers.ProjectHandler
	Access  *handlers.AccessHandler
	Audit   *handlers.AuditHandler
}

// SetupRoutes configures all application routes
func SetupRoutes(router *gin.Engine, handlers *Handlers, jwtSecret string) {
	// Add global middleware
	router.Use(middleware.SetUserContext())

	// Health check endpoint (no auth required)
	router.GET("/health", healthCheck)
	router.GET("/", healthCheck)

	// API version 1
	v1 := router.Group("/api")
	{
		// Authentication routes (no auth required)
		auth := v1.Group("/auth")
		{
			auth.POST("/login", handlers.User.Login)
			auth.POST("/refresh", handlers.User.RefreshToken)
			auth.POST("/forgot-password", handlers.User.ForgotPassword)
			auth.POST("/reset-password", handlers.User.ResetPassword)
		}

		// Public information endpoints (no auth required)
		public := v1.Group("/public")
		{
			public.GET("/platforms", handlers.Server.GetPlatforms)
			public.GET("/environments", getEnvironments)
			public.GET("/server-stats", handlers.Server.GetServerDistribution)
		}

		// Protected routes (require authentication)
		protected := v1.Group("", middleware.AuthMiddleware(jwtSecret))
		{
			// User routes
			users := protected.Group("/users")
			{
				users.GET("", handlers.User.ListUsers)
				users.POST("", middleware.RequireRole("admin"), handlers.User.CreateUser)
				users.GET("/search", handlers.User.SearchUsers)
				users.POST("/bulk", middleware.RequireRole("admin"), handlers.User.BulkCreateUsers)
				users.GET("/export", middleware.RequireRole("admin"), handlers.User.ExportUsers)
				users.POST("/import", middleware.RequireRole("admin"), handlers.User.ImportUsers)

				// User-specific routes
				userRoutes := users.Group("/:id")
				userRoutes.Use(middleware.RequireUserOrAdmin())
				{
					userRoutes.GET("", handlers.User.GetUser)
					userRoutes.PUT("", handlers.User.UpdateUser)
					userRoutes.DELETE("", middleware.RequireRole("admin"), handlers.User.DeleteUser)

					// User actions
					userRoutes.POST("/activate", middleware.RequireRole("admin"), handlers.User.ActivateUser)
					userRoutes.POST("/deactivate", middleware.RequireRole("admin"), handlers.User.DeactivateUser)
					userRoutes.POST("/ban", middleware.RequireRole("admin"), handlers.User.BanUser)
					userRoutes.POST("/change-password", handlers.User.ChangePassword)

					// User profile
					userRoutes.GET("/profile", handlers.User.GetUserProfile)
					userRoutes.PUT("/profile", handlers.User.UpdateUserProfile)
					userRoutes.GET("/stats", handlers.User.GetUserStats)
					userRoutes.GET("/activity", handlers.User.GetUserActivity)

					// SSH keys
					sshKeys := userRoutes.Group("/ssh-keys")
					{
						sshKeys.GET("", handlers.User.GetUserSSHKeys)
						sshKeys.POST("", handlers.User.AddSSHKey)
						sshKeys.PUT("/:key_id", handlers.User.UpdateSSHKey)
						sshKeys.DELETE("/:key_id", handlers.User.DeleteSSHKey)
					}

					// User groups and projects
					userRoutes.GET("/groups", handlers.User.GetUserGroups)
					userRoutes.GET("/projects", handlers.User.GetUserProjects)
					userRoutes.GET("/access-history", handlers.User.GetUserAccessHistory)
				}
			}

			// Server routes
			servers := protected.Group("/servers")
			{
				servers.GET("", handlers.Server.ListServers)
				servers.POST("", middleware.RequirePermission("manage_servers"), handlers.Server.CreateServer)
				servers.GET("/search", handlers.Server.SearchServers)
				servers.GET("/tags", handlers.Server.GetAllTags)
				servers.GET("/platforms/summary", handlers.Server.GetPlatformSummary)
				servers.GET("/environments/summary", handlers.Server.GetEnvironmentSummary)
				servers.GET("/distribution", handlers.Server.GetServerDistribution)
				servers.POST("/bulk", middleware.RequireRole("admin"), handlers.Server.BulkCreateServers)
				servers.POST("/bulk/update", middleware.RequireRole("admin"), handlers.Server.BulkUpdateServers)
				servers.POST("/bulk/delete", middleware.RequireRole("admin"), handlers.Server.BulkDeleteServers)

				// Server-specific routes
				serverRoutes := servers.Group("/:id")
				{
					serverRoutes.GET("", handlers.Server.GetServer)
					serverRoutes.PUT("", middleware.RequirePermission("manage_servers"), handlers.Server.UpdateServer)
					serverRoutes.DELETE("", middleware.RequireRole("admin"), handlers.Server.DeleteServer)

					// Server actions
					serverRoutes.POST("/activate", middleware.RequirePermission("manage_servers"), handlers.Server.ActivateServer)
					serverRoutes.POST("/deactivate", middleware.RequirePermission("manage_servers"), handlers.Server.DeactivateServer)
					serverRoutes.POST("/test-connectivity", middleware.RequirePermission("manage_servers"), handlers.Server.TestServerConnectivity)

					// Server information
					serverRoutes.GET("/stats", handlers.Server.GetServerStats)
					serverRoutes.GET("/access", handlers.Server.GetServerAccess)
					serverRoutes.GET("/users", handlers.Server.GetServerUsers)
					serverRoutes.GET("/sessions", handlers.Server.GetServerSessions)

					// Server tags
					serverRoutes.POST("/tags", middleware.RequirePermission("manage_servers"), handlers.Server.AddServerTags)
					serverRoutes.DELETE("/tags", middleware.RequirePermission("manage_servers"), handlers.Server.RemoveServerTags)

					// Server groups and projects
					serverRoutes.POST("/groups/:group_id", middleware.RequirePermission("manage_servers"), handlers.Server.AddToGroup)
					serverRoutes.DELETE("/groups/:group_id", middleware.RequirePermission("manage_servers"), handlers.Server.RemoveFromGroup)
					serverRoutes.POST("/projects/:project_id", middleware.RequirePermission("manage_servers"), handlers.Server.AddToProject)
					serverRoutes.DELETE("/projects/:project_id", middleware.RequirePermission("manage_servers"), handlers.Server.RemoveFromProject)
				}
			}

			// Group routes
			groups := protected.Group("/groups")
			{
				groups.GET("", handlers.Group.ListGroups)
				groups.POST("", middleware.RequirePermission("manage_groups"), handlers.Group.CreateGroup)
				groups.GET("/search", handlers.Group.SearchGroups)
				groups.GET("/tree", handlers.Group.GetGroupTree)

				// Group-specific routes
				groupRoutes := groups.Group("/:id")
				{
					groupRoutes.GET("", handlers.Group.GetGroup)
					groupRoutes.PUT("", middleware.RequirePermission("manage_groups"), handlers.Group.UpdateGroup)
					groupRoutes.DELETE("", middleware.RequireRole("admin"), handlers.Group.DeleteGroup)

					// Group members
					groupRoutes.GET("/users", handlers.Group.GetGroupUsers)
					groupRoutes.POST("/users", middleware.RequirePermission("manage_groups"), handlers.Group.AddUsersToGroup)
					groupRoutes.DELETE("/users", middleware.RequirePermission("manage_groups"), handlers.Group.RemoveUsersFromGroup)

					// Group servers
					groupRoutes.GET("/servers", handlers.Group.GetGroupServers)
					groupRoutes.POST("/servers", middleware.RequirePermission("manage_groups"), handlers.Group.AddServersToGroup)
					groupRoutes.DELETE("/servers", middleware.RequirePermission("manage_groups"), handlers.Group.RemoveServersFromGroup)

					// Group stats
					groupRoutes.GET("/stats", handlers.Group.GetGroupStats)
				}
			}

			// Project routes
			projects := protected.Group("/projects")
			{
				projects.GET("", handlers.Project.ListProjects)
				projects.POST("", middleware.RequirePermission("manage_projects"), handlers.Project.CreateProject)
				projects.GET("/search", handlers.Project.SearchProjects)

				// Project-specific routes
				projectRoutes := projects.Group("/:id")
				{
					projectRoutes.GET("", handlers.Project.GetProject)
					projectRoutes.PUT("", middleware.RequirePermission("manage_projects"), handlers.Project.UpdateProject)
					projectRoutes.DELETE("", middleware.RequireRole("admin"), handlers.Project.DeleteProject)

					// Project members
					projectRoutes.GET("/users", handlers.Project.GetProjectUsers)
					projectRoutes.POST("/users", middleware.RequirePermission("manage_projects"), handlers.Project.AddUsersToProject)
					projectRoutes.DELETE("/users", middleware.RequirePermission("manage_projects"), handlers.Project.RemoveUsersFromProject)

					// Project groups
					projectRoutes.GET("/groups", handlers.Project.GetProjectGroups)
					projectRoutes.POST("/groups", middleware.RequirePermission("manage_projects"), handlers.Project.AddGroupsToProject)
					projectRoutes.DELETE("/groups", middleware.RequirePermission("manage_projects"), handlers.Project.RemoveGroupsFromProject)

					// Project servers
					projectRoutes.GET("/servers", handlers.Project.GetProjectServers)
					projectRoutes.POST("/servers", middleware.RequirePermission("manage_projects"), handlers.Project.AddServersToProject)
					projectRoutes.DELETE("/servers", middleware.RequirePermission("manage_projects"), handlers.Project.RemoveServersFromProject)

					// Project stats
					projectRoutes.GET("/stats", handlers.Project.GetProjectStats)
				}
			}

			// Access management routes
			access := protected.Group("/access")
			{
				// Access grants
				grants := access.Group("/grants")
				{
					grants.GET("", handlers.Access.ListAccessGrants)
					grants.POST("", middleware.RequirePermission("grant_access"), handlers.Access.GrantAccess)
					grants.GET("/:id", handlers.Access.GetAccessGrant)
					grants.PUT("/:id", middleware.RequirePermission("grant_access"), handlers.Access.UpdateAccessGrant)
					grants.DELETE("/:id", middleware.RequirePermission("revoke_access"), handlers.Access.RevokeAccess)
				}

				// Access requests
				requests := access.Group("/requests")
				{
					requests.GET("", handlers.Access.ListAccessRequests)
					requests.POST("", handlers.Access.CreateAccessRequest)
					requests.GET("/:id", handlers.Access.GetAccessRequest)
					requests.POST("/:id/approve", middleware.RequirePermission("grant_access"), handlers.Access.ApproveAccessRequest)
					requests.POST("/:id/reject", middleware.RequirePermission("grant_access"), handlers.Access.RejectAccessRequest)
				}

				// User access
				access.GET("/user/:user_id", handlers.Access.GetUserAccess)
				access.GET("/server/:server_id", handlers.Access.GetServerAccess)
				access.GET("/effective/:user_id", handlers.Access.GetUserEffectiveAccess)

				// Access sessions
				sessions := access.Group("/sessions")
				{
					sessions.GET("", handlers.Access.ListActiveSessions)
					sessions.GET("/:id", handlers.Access.GetSession)
					sessions.DELETE("/:id", middleware.RequirePermission("manage_sessions"), handlers.Access.TerminateSession)
				}

				// Access statistics
				access.GET("/stats", handlers.Access.GetAccessStats)
				access.GET("/trends", handlers.Access.GetAccessTrends)
			}

			// Audit routes
			audits := protected.Group("/audits")
			{
				audits.GET("", middleware.RequirePermission("view_audit_logs"), handlers.Audit.ListAuditLogs)
				audits.GET("/:id", middleware.RequirePermission("view_audit_logs"), handlers.Audit.GetAuditLog)
				audits.GET("/search", middleware.RequirePermission("view_audit_logs"), handlers.Audit.SearchAuditLogs)
				audits.GET("/export", middleware.RequireRole("admin"), handlers.Audit.ExportAuditLogs)

				// Audit statistics
				audits.GET("/stats", middleware.RequirePermission("view_audit_logs"), handlers.Audit.GetAuditStats)
				audits.GET("/security-events", middleware.RequirePermission("view_audit_logs"), handlers.Audit.GetSecurityEvents)
				audits.GET("/trends", middleware.RequirePermission("view_audit_logs"), handlers.Audit.GetActivityTrends)

				// Audit reports
				reports := audits.Group("/reports")
				reports.Use(middleware.RequireRole("admin"))
				{
					reports.GET("/compliance", handlers.Audit.GetComplianceReport)
					reports.GET("/access", handlers.Audit.GetAccessReport)
					reports.GET("/security", handlers.Audit.GetSecurityReport)
					reports.GET("/user/:user_id", handlers.Audit.GetUserActivityReport)
					reports.GET("/server/:server_id", handlers.Audit.GetServerActivityReport)
				}
			}

			// Admin-only routes
			admin := protected.Group("/admin")
			admin.Use(middleware.RequireRole("admin"))
			{
				// System information
				admin.GET("/info", getSystemInfo)
				admin.GET("/health/detailed", getDetailedHealth)
				admin.GET("/metrics", getSystemMetrics)

				// Database operations
				admin.POST("/database/optimize", optimizeDatabase)
				admin.POST("/database/backup", backupDatabase)
				admin.GET("/database/stats", getDatabaseStats)

				// System maintenance
				admin.POST("/maintenance/cleanup", cleanupSystem)
				admin.POST("/maintenance/cache/clear", clearCache)
				admin.GET("/maintenance/status", getMaintenanceStatus)
			}
		}
	}

	// Setup 404 handler
	router.NoRoute(func(c *gin.Context) {
		c.JSON(404, gin.H{
			"success": false,
			"message": "Route not found",
			"error": gin.H{
				"code":    "ROUTE_NOT_FOUND",
				"details": "The requested route does not exist",
			},
			"timestamp": "2023-12-01T12:00:00Z",
		})
	})
}

// Health check handler
func healthCheck(c *gin.Context) {
	c.JSON(200, gin.H{
		"success": true,
		"message": "SSH Access Management API is running",
		"data": gin.H{
			"status":    "healthy",
			"version":   "1.0.0",
			"timestamp": "2023-12-01T12:00:00Z",
		},
	})
}

// Get environments handler
func getEnvironments(c *gin.Context) {
	environments := []string{"production", "staging", "dev", "test"}
	c.JSON(200, gin.H{
		"success": true,
		"message": "Environments retrieved successfully",
		"data":    environments,
	})
}

// Admin handlers (placeholder implementations)
func getSystemInfo(c *gin.Context) {
	c.JSON(200, gin.H{
		"success": true,
		"message": "System information retrieved",
		"data": gin.H{
			"version":      "1.0.0",
			"go_version":   "1.21",
			"platform":     "linux/amd64",
			"uptime":       "24h30m",
			"memory_usage": "256MB",
		},
	})
}

func getDetailedHealth(c *gin.Context) {
	c.JSON(200, gin.H{
		"success": true,
		"message": "Detailed health check completed",
		"data": gin.H{
			"status": "healthy",
			"services": gin.H{
				"database":     "healthy",
				"cache":        "healthy",
				"external_api": "healthy",
			},
			"metrics": gin.H{
				"response_time": "15ms",
				"memory_usage":  "256MB",
				"cpu_usage":     "12%",
			},
		},
	})
}

func getSystemMetrics(c *gin.Context) {
	c.JSON(200, gin.H{
		"success": true,
		"message": "System metrics retrieved",
		"data": gin.H{
			"requests_per_minute":  120,
			"active_sessions":      45,
			"database_connections": 10,
			"memory_usage":         "256MB",
			"cpu_usage":            "12%",
			"disk_usage":           "45%",
		},
	})
}

func optimizeDatabase(c *gin.Context) {
	c.JSON(200, gin.H{
		"success": true,
		"message": "Database optimization started",
		"data": gin.H{
			"job_id": "opt_123456",
			"status": "running",
		},
	})
}

func backupDatabase(c *gin.Context) {
	c.JSON(200, gin.H{
		"success": true,
		"message": "Database backup started",
		"data": gin.H{
			"backup_id": "backup_123456",
			"status":    "running",
		},
	})
}

func getDatabaseStats(c *gin.Context) {
	c.JSON(200, gin.H{
		"success": true,
		"message": "Database statistics retrieved",
		"data": gin.H{
			"total_size":         "1.2GB",
			"tables":             12,
			"total_records":      15420,
			"active_connections": 8,
			"query_performance":  "good",
		},
	})
}

func cleanupSystem(c *gin.Context) {
	c.JSON(200, gin.H{
		"success": true,
		"message": "System cleanup started",
		"data": gin.H{
			"job_id": "cleanup_123456",
			"status": "running",
		},
	})
}

func clearCache(c *gin.Context) {
	c.JSON(200, gin.H{
		"success": true,
		"message": "Cache cleared successfully",
		"data": gin.H{
			"cache_size_before": "128MB",
			"cache_size_after":  "0MB",
		},
	})
}

func getMaintenanceStatus(c *gin.Context) {
	c.JSON(200, gin.H{
		"success": true,
		"message": "Maintenance status retrieved",
		"data": gin.H{
			"maintenance_mode": false,
			"last_cleanup":     "2023-12-01T06:00:00Z",
			"next_maintenance": "2023-12-02T06:00:00Z",
			"running_jobs":     []string{},
		},
	})
}
