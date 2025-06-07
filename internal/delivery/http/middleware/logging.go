package middleware

import (
	"bytes"
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
			"client_ip":  clientIP,
			"method":     c.Request.Method,
			"path":       path,
			"status":     c.Writer.Status(),
			"latency":    latency,
			"user_agent": c.Request.UserAgent(),
			"request_id": requestID,
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
