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
