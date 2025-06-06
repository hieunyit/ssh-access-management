// cors.go
package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// CORS creates CORS middleware
func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		
		// Allow specific origins or all origins in development
		if origin != "" {
			c.Header("Access-Control-Allow-Origin", origin)
		} else {
			c.Header("Access-Control-Allow-Origin", "*")
		}
		
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, X-Requested-With")
		c.Header("Access-Control-Expose-Headers", "Content-Length, X-Request-ID")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400")

		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// logging.go
package middleware

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type responseWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (r responseWriter) Write(b []byte) (int, error) {
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}

// Logger creates logging middleware
func Logger(logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Read request body
		var requestBody []byte
		if c.Request.Body != nil {
			requestBody, _ = io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(requestBody))
		}

		// Wrap response writer to capture response body
		responseWriter := &responseWriter{
			ResponseWriter: c.Writer,
			body:           bytes.NewBufferString(""),
		}
		c.Writer = responseWriter

		c.Next()

		// Calculate processing time
		latency := time.Since(start)

		// Get client IP
		clientIP := getClientIP(c)

		// Build full path
		if raw != "" {
			path = path + "?" + raw
		}

		// Get user information from context
		userID, _ := c.Get("user_id")
		username, _ := c.Get("username")
		requestID, _ := c.Get("request_id")

		// Create log entry
		entry := logger.WithFields(logrus.Fields{
			"client_ip":   clientIP,
			"method":      c.Request.Method,
			"path":        path,
			"status":      c.Writer.Status(),
			"latency":     latency,
			"user_agent":  c.Request.UserAgent(),
			"request_id":  requestID,
		})

		// Add user information if authenticated
		if userID != nil {
			entry = entry.WithField("user_id", userID)
		}
		if username != nil {
			entry = entry.WithField("username", username)
		}

		// Log request body for write operations (POST, PUT, PATCH)
		if c.Request.Method != "GET" && len(requestBody) > 0 && len(requestBody) < 1024 {
			entry = entry.WithField("request_body", string(requestBody))
		}

		// Log response body for errors
		if c.Writer.Status() >= 400 && responseWriter.body.Len() > 0 && responseWriter.body.Len() < 1024 {
			entry = entry.WithField("response_body", responseWriter.body.String())
		}

		// Choose log level based on status code
		status := c.Writer.Status()
		switch {
		case status >= 500:
			entry.Error("HTTP request completed with server error")
		case status >= 400:
			entry.Warn("HTTP request completed with client error")
		case status >= 300:
			entry.Info("HTTP request completed with redirect")
		default:
			entry.Info("HTTP request completed successfully")
		}
	}
}

// rate_limit.go
package middleware

import (
	"net/http"
	"sync"
	"time"

	"ssh-access-management/internal/delivery/http/response"

	"github.com/gin-gonic/gin"
)

// RateLimiter represents a rate limiter
type RateLimiter struct {
	visitors map[string]*visitor
	mutex    sync.RWMutex
	rate     time.Duration
	burst    int
}

type visitor struct {
	lastSeen time.Time
	tokens   int
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rate time.Duration, burst int) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate,
		burst:    burst,
	}

	// Start cleanup routine
	go rl.cleanup()

	return rl
}

// Allow checks if the request is allowed
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	v, exists := rl.visitors[ip]

	if !exists {
		rl.visitors[ip] = &visitor{
			lastSeen: now,
			tokens:   rl.burst - 1,
		}
		return true
	}

	// Add tokens based on time elapsed
	elapsed := now.Sub(v.lastSeen)
	tokensToAdd := int(elapsed / rl.rate)
	v.tokens += tokensToAdd

	if v.tokens > rl.burst {
		v.tokens = rl.burst
	}

	v.lastSeen = now

	if v.tokens > 0 {
		v.tokens--
		return true
	}

	return false
}

// cleanup removes old visitors
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.mutex.Lock()
			cutoff := time.Now().Add(-time.Hour)
			for ip, v := range rl.visitors {
				if v.lastSeen.Before(cutoff) {
					delete(rl.visitors, ip)
				}
			}
			rl.mutex.Unlock()
		}
	}
}

// Global rate limiter instance
var globalRateLimiter *RateLimiter

// RateLimit creates rate limiting middleware
func RateLimit() gin.HandlerFunc {
	if globalRateLimiter == nil {
		// Default: 100 requests per minute with burst of 10
		globalRateLimiter = NewRateLimiter(600*time.Millisecond, 10)
	}

	return func(c *gin.Context) {
		clientIP := getClientIP(c)

		if !globalRateLimiter.Allow(clientIP) {
			response.Error(c, http.StatusTooManyRequests, "Rate limit exceeded", "Too many requests from this IP address")
			c.Abort()
			return
		}

		c.Next()
	}
}

// StrictRateLimit creates stricter rate limiting middleware
func StrictRateLimit() gin.HandlerFunc {
	strictLimiter := NewRateLimiter(2*time.Second, 5) // 30 requests per minute with burst of 5

	return func(c *gin.Context) {
		clientIP := getClientIP(c)

		if !strictLimiter.Allow(clientIP) {
			response.Error(c, http.StatusTooManyRequests, "Rate limit exceeded", "Too many requests from this IP address")
			c.Abort()
			return
		}

		c.Next()
	}
}

// APIKeyRateLimit creates API key specific rate limiting
func APIKeyRateLimit() gin.HandlerFunc {
	apiKeyLimiter := NewRateLimiter(100*time.Millisecond, 50) // 600 requests per minute

	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			// Fall back to IP-based rate limiting
			clientIP := getClientIP(c)
			if !globalRateLimiter.Allow(clientIP) {
				response.Error(c, http.StatusTooManyRequests, "Rate limit exceeded", "Too many requests")
				c.Abort()
				return
			}
		} else {
			if !apiKeyLimiter.Allow(apiKey) {
				response.Error(c, http.StatusTooManyRequests, "API rate limit exceeded", "Too many API requests")
				c.Abort()
				return
			}
		}

		c.Next()
	}
}