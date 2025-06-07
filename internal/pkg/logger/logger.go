package logger

import (
	"context"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

// Logger wraps logrus with additional functionality
type Logger struct {
	*logrus.Logger
}

// Fields represents log fields
type Fields map[string]interface{}

// NewLogger creates a new logger instance
func NewLogger(level string) *Logger {
	log := logrus.New()

	// Set log level
	switch level {
	case "debug":
		log.SetLevel(logrus.DebugLevel)
	case "info":
		log.SetLevel(logrus.InfoLevel)
	case "warn":
		log.SetLevel(logrus.WarnLevel)
	case "error":
		log.SetLevel(logrus.ErrorLevel)
	default:
		log.SetLevel(logrus.InfoLevel)
	}

	// Set JSON formatter for production
	log.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "message",
		},
	})

	// Set output to stdout
	log.SetOutput(os.Stdout)

	return &Logger{log}
}

// WithContext adds context to logger
func (l *Logger) WithContext(ctx context.Context) *logrus.Entry {
	entry := l.WithField("correlation_id", getCorrelationID(ctx))

	if userID := getUserID(ctx); userID != "" {
		entry = entry.WithField("user_id", userID)
	}

	if requestID := getRequestID(ctx); requestID != "" {
		entry = entry.WithField("request_id", requestID)
	}

	return entry
}

// WithFields adds fields to logger
func (l *Logger) WithFields(fields Fields) *logrus.Entry {
	return l.Logger.WithFields(logrus.Fields(fields))
}

// LogRequest logs HTTP request
func (l *Logger) LogRequest(method, path, clientIP, userAgent string, statusCode int, duration time.Duration) {
	l.WithFields(Fields{
		"method":      method,
		"path":        path,
		"client_ip":   clientIP,
		"user_agent":  userAgent,
		"status_code": statusCode,
		"duration_ms": duration.Milliseconds(),
		"type":        "http_request",
	}).Info("HTTP request processed")
}

// LogDBQuery logs database queries
func (l *Logger) LogDBQuery(query string, duration time.Duration, err error) {
	fields := Fields{
		"query":       query,
		"duration_ms": duration.Milliseconds(),
		"type":        "db_query",
	}

	if err != nil {
		fields["error"] = err.Error()
		l.WithFields(fields).Error("Database query failed")
	} else {
		l.WithFields(fields).Debug("Database query executed")
	}
}

// LogSecurityEvent logs security-related events
func (l *Logger) LogSecurityEvent(event, userID, clientIP, details string) {
	l.WithFields(Fields{
		"event":     event,
		"user_id":   userID,
		"client_ip": clientIP,
		"details":   details,
		"type":      "security_event",
		"severity":  "high",
	}).Warn("Security event detected")
}

// LogBusinessEvent logs business logic events
func (l *Logger) LogBusinessEvent(event, entity string, entityID uint, userID string, details string) {
	l.WithFields(Fields{
		"event":     event,
		"entity":    entity,
		"entity_id": entityID,
		"user_id":   userID,
		"details":   details,
		"type":      "business_event",
	}).Info("Business event occurred")
}

// LogError logs errors with stack trace
func (l *Logger) LogError(err error, context string, fields Fields) {
	if fields == nil {
		fields = Fields{}
	}

	fields["error"] = err.Error()
	fields["context"] = context
	fields["type"] = "error"

	l.WithFields(fields).Error("Error occurred")
}

// Helper functions to extract context values
func getCorrelationID(ctx context.Context) string {
	if id, ok := ctx.Value("correlation_id").(string); ok {
		return id
	}
	return ""
}

func getUserID(ctx context.Context) string {
	if id, ok := ctx.Value("user_id").(string); ok {
		return id
	}
	return ""
}

func getRequestID(ctx context.Context) string {
	if id, ok := ctx.Value("request_id").(string); ok {
		return id
	}
	return ""
}
