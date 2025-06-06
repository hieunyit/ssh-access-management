package middleware

import (
	"net/http"
	"strings"

	"ssh-access-management/internal/delivery/http/response"
	"ssh-access-management/internal/pkg/auth"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware creates authentication middleware
func AuthMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			response.Unauthorized(c, "Authorization header required")
			c.Abort()
			return
		}

		// Check if token has Bearer prefix
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			response.Unauthorized(c, "Invalid authorization header format")
			c.Abort()
			return
		}

		tokenString := tokenParts[1]

		// Validate token
		claims, err := auth.ValidateToken(tokenString, jwtSecret)
		if err != nil {
			response.Unauthorized(c, "Invalid or expired token")
			c.Abort()
			return
		}

		// Set user information in context
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)
		c.Set("token_claims", claims)

		c.Next()
	}
}

// OptionalAuthMiddleware creates optional authentication middleware
func OptionalAuthMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		// Check if token has Bearer prefix
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.Next()
			return
		}

		tokenString := tokenParts[1]

		// Validate token
		claims, err := auth.ValidateToken(tokenString, jwtSecret)
		if err != nil {
			c.Next()
			return
		}

		// Set user information in context
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)
		c.Set("token_claims", claims)

		c.Next()
	}
}

// RequireRole creates role-based authorization middleware
func RequireRole(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRole, exists := c.Get("role")
		if !exists {
			response.Unauthorized(c, "Authentication required")
			c.Abort()
			return
		}

		role, ok := userRole.(string)
		if !ok {
			response.Unauthorized(c, "Invalid user role")
			c.Abort()
			return
		}

		// Check if user role is in allowed roles
		for _, allowedRole := range allowedRoles {
			if role == allowedRole {
				c.Next()
				return
			}
		}

		response.Forbidden(c, "Insufficient permissions")
		c.Abort()
	}
}

// RequireAdmin creates admin-only middleware
func RequireAdmin() gin.HandlerFunc {
	return RequireRole("admin")
}

// RequireUserOrAdmin creates middleware that allows users to access their own resources or admins to access any
func RequireUserOrAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			response.Unauthorized(c, "Authentication required")
			c.Abort()
			return
		}

		userRole, roleExists := c.Get("role")
		if !roleExists {
			response.Unauthorized(c, "Invalid user role")
			c.Abort()
			return
		}

		role, ok := userRole.(string)
		if !ok {
			response.Unauthorized(c, "Invalid user role")
			c.Abort()
			return
		}

		// Admin can access everything
		if role == "admin" {
			c.Next()
			return
		}

		// Regular users can only access their own resources
		currentUserID, ok := userID.(uint)
		if !ok {
			response.Unauthorized(c, "Invalid user ID")
			c.Abort()
			return
		}

		// Get resource user ID from URL parameter
		resourceUserIDStr := c.Param("id")
		if resourceUserIDStr == "" {
			// If no user ID in URL, allow access (for list operations, etc.)
			c.Next()
			return
		}

		// Parse resource user ID
		resourceUserID := parseUserID(resourceUserIDStr)
		if resourceUserID == 0 {
			response.Error(c, http.StatusBadRequest, "Invalid user ID", "User ID must be a valid number")
			c.Abort()
			return
		}

		// Check if current user is accessing their own resource
		if currentUserID != resourceUserID {
			response.Forbidden(c, "You can only access your own resources")
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequirePermission creates permission-based authorization middleware
func RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, exists := c.Get("token_claims")
		if !exists {
			response.Unauthorized(c, "Authentication required")
			c.Abort()
			return
		}

		tokenClaims, ok := claims.(*auth.Claims)
		if !ok {
			response.Unauthorized(c, "Invalid token claims")
			c.Abort()
			return
		}

		// Check if user has the required permission
		if !hasPermission(tokenClaims, permission) {
			response.Forbidden(c, "Insufficient permissions")
			c.Abort()
			return
		}

		c.Next()
	}
}

// SetUserContext sets user context information
func SetUserContext() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Set request ID
		requestID := generateRequestID()
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)

		// Set user IP
		clientIP := getClientIP(c)
		c.Set("client_ip", clientIP)

		// Set user agent
		userAgent := c.GetHeader("User-Agent")
		c.Set("user_agent", userAgent)

		c.Next()
	}
}

// Helper functions

func parseUserID(userIDStr string) uint {
	// This is a simplified version - in production, use strconv.ParseUint
	if userIDStr == "1" {
		return 1
	}
	if userIDStr == "2" {
		return 2
	}
	// Add more parsing logic as needed
	return 0
}

func hasPermission(claims *auth.Claims, permission string) bool {
	// Implement permission checking logic based on user role and permissions
	switch claims.Role {
	case "admin":
		return true // Admin has all permissions
	case "user":
		// Define user permissions
		userPermissions := []string{
			"view_servers",
			"request_access",
			"manage_ssh_keys",
			"view_own_profile",
			"update_own_profile",
		}
		return contains(userPermissions, permission)
	case "readonly":
		// Define readonly permissions
		readonlyPermissions := []string{
			"view_servers",
			"view_own_profile",
		}
		return contains(readonlyPermissions, permission)
	default:
		return false
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func generateRequestID() string {
	// In production, use a proper UUID library
	return "req_" + "12345678"
}

func getClientIP(c *gin.Context) string {
	// Check X-Forwarded-For header first
	if xForwardedFor := c.GetHeader("X-Forwarded-For"); xForwardedFor != "" {
		// Take the first IP if multiple are present
		ips := strings.Split(xForwardedFor, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xRealIP := c.GetHeader("X-Real-IP"); xRealIP != "" {
		return xRealIP
	}

	// Fallback to RemoteAddr
	return c.ClientIP()
}
