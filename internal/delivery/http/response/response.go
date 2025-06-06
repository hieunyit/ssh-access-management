package response

import (
	"net/http"
	"strings"

	"ssh-access-management/internal/domain/entities"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

// Response represents standard API response format
type Response struct {
	Success   bool        `json:"success"`
	Message   string      `json:"message"`
	Data      interface{} `json:"data,omitempty"`
	Error     *ErrorInfo  `json:"error,omitempty"`
	Meta      *Meta       `json:"meta,omitempty"`
	Timestamp string      `json:"timestamp"`
}

// ErrorInfo represents error information
type ErrorInfo struct {
	Code    string                 `json:"code"`
	Details string                 `json:"details,omitempty"`
	Fields  map[string]string      `json:"fields,omitempty"`
	Context map[string]interface{} `json:"context,omitempty"`
}

// Meta represents response metadata
type Meta struct {
	RequestID   string      `json:"request_id,omitempty"`
	Version     string      `json:"version,omitempty"`
	Pagination  interface{} `json:"pagination,omitempty"`
	Total       *int64      `json:"total,omitempty"`
	Count       *int        `json:"count,omitempty"`
	ProcessTime string      `json:"process_time,omitempty"`
}

// Success sends a successful response
func Success(c *gin.Context, statusCode int, message string, data interface{}) {
	response := Response{
		Success:   true,
		Message:   message,
		Data:      data,
		Timestamp: getCurrentTimestamp(),
	}

	// Add request ID if available
	if requestID := c.GetString("request_id"); requestID != "" {
		if response.Meta == nil {
			response.Meta = &Meta{}
		}
		response.Meta.RequestID = requestID
	}

	// Add count for slices/arrays
	if data != nil {
		switch v := data.(type) {
		case []interface{}:
			count := len(v)
			if response.Meta == nil {
				response.Meta = &Meta{}
			}
			response.Meta.Count = &count
		}
	}

	c.JSON(statusCode, response)
}

// Error sends an error response
func Error(c *gin.Context, statusCode int, message, details string) {
	response := Response{
		Success: false,
		Message: message,
		Error: &ErrorInfo{
			Code:    getErrorCode(statusCode),
			Details: details,
		},
		Timestamp: getCurrentTimestamp(),
	}

	// Add request ID if available
	if requestID := c.GetString("request_id"); requestID != "" {
		if response.Meta == nil {
			response.Meta = &Meta{}
		}
		response.Meta.RequestID = requestID
	}

	c.JSON(statusCode, response)
}

// ValidationError sends a validation error response
func ValidationError(c *gin.Context, err error) {
	errorInfo := &ErrorInfo{
		Code:   "VALIDATION_ERROR",
		Fields: make(map[string]string),
	}

	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		for _, validationError := range validationErrors {
			field := strings.ToLower(validationError.Field())
			tag := validationError.Tag()

			switch tag {
			case "required":
				errorInfo.Fields[field] = "This field is required"
			case "email":
				errorInfo.Fields[field] = "Must be a valid email address"
			case "min":
				errorInfo.Fields[field] = "Value is too short"
			case "max":
				errorInfo.Fields[field] = "Value is too long"
			case "oneof":
				errorInfo.Fields[field] = "Invalid value"
			case "ip":
				errorInfo.Fields[field] = "Must be a valid IP address"
			default:
				errorInfo.Fields[field] = "Invalid value"
			}
		}
	} else {
		errorInfo.Details = err.Error()
	}

	response := Response{
		Success:   false,
		Message:   "Validation failed",
		Error:     errorInfo,
		Timestamp: getCurrentTimestamp(),
	}

	// Add request ID if available
	if requestID := c.GetString("request_id"); requestID != "" {
		if response.Meta == nil {
			response.Meta = &Meta{}
		}
		response.Meta.RequestID = requestID
	}

	c.JSON(http.StatusBadRequest, response)
}

// HandleServiceError handles service layer errors and maps them to appropriate HTTP responses
func HandleServiceError(c *gin.Context, err error) {
	var statusCode int
	var message string
	var errorCode string

	// Map domain errors to HTTP status codes
	switch err {
	// User errors
	case entities.ErrUserNotFound:
		statusCode = http.StatusNotFound
		message = "User not found"
		errorCode = string(entities.CodeUserNotFound)
	case entities.ErrUserAlreadyExists:
		statusCode = http.StatusConflict
		message = "User already exists"
		errorCode = string(entities.CodeUserAlreadyExists)
	case entities.ErrInvalidUserCredentials:
		statusCode = http.StatusUnauthorized
		message = "Invalid credentials"
		errorCode = string(entities.CodeInvalidCredentials)
	case entities.ErrUserInactive:
		statusCode = http.StatusForbidden
		message = "User account is inactive"
		errorCode = string(entities.CodeUserInactive)
	case entities.ErrUserBanned:
		statusCode = http.StatusForbidden
		message = "User account is banned"
		errorCode = string(entities.CodeUserBanned)
	case entities.ErrWeakPassword:
		statusCode = http.StatusBadRequest
		message = "Password does not meet security requirements"
		errorCode = string(entities.CodeValidationFailed)

	// Server errors
	case entities.ErrServerNotFound:
		statusCode = http.StatusNotFound
		message = "Server not found"
		errorCode = string(entities.CodeServerNotFound)
	case entities.ErrServerAlreadyExists:
		statusCode = http.StatusConflict
		message = "Server already exists"
		errorCode = string(entities.CodeServerAlreadyExists)
	case entities.ErrServerInactive:
		statusCode = http.StatusForbidden
		message = "Server is inactive"
		errorCode = string(entities.CodeServerInactive)
	case entities.ErrServerConnectionFailed:
		statusCode = http.StatusServiceUnavailable
		message = "Failed to connect to server"
		errorCode = string(entities.CodeServerConnectionFailed)

	// Group errors
	case entities.ErrGroupNotFound:
		statusCode = http.StatusNotFound
		message = "Group not found"
		errorCode = string(entities.CodeGroupNotFound)
	case entities.ErrGroupAlreadyExists:
		statusCode = http.StatusConflict
		message = "Group already exists"
		errorCode = string(entities.CodeGroupAlreadyExists)
	case entities.ErrCircularGroupDependency:
		statusCode = http.StatusBadRequest
		message = "Circular group dependency detected"
		errorCode = string(entities.CodeCircularDependency)

	// Project errors
	case entities.ErrProjectNotFound:
		statusCode = http.StatusNotFound
		message = "Project not found"
		errorCode = string(entities.CodeProjectNotFound)
	case entities.ErrProjectAlreadyExists:
		statusCode = http.StatusConflict
		message = "Project already exists"
		errorCode = string(entities.CodeProjectAlreadyExists)
	case entities.ErrProjectInactive:
		statusCode = http.StatusForbidden
		message = "Project is inactive"
		errorCode = string(entities.CodeProjectInactive)

	// Access errors
	case entities.ErrAccessNotFound:
		statusCode = http.StatusNotFound
		message = "Access grant not found"
		errorCode = string(entities.CodeAccessNotFound)
	case entities.ErrAccessExpired:
		statusCode = http.StatusForbidden
		message = "Access grant has expired"
		errorCode = string(entities.CodeAccessExpired)
	case entities.ErrAccessRevoked:
		statusCode = http.StatusForbidden
		message = "Access grant has been revoked"
		errorCode = string(entities.CodeAccessRevoked)
	case entities.ErrInsufficientPermission:
		statusCode = http.StatusForbidden
		message = "Insufficient permissions"
		errorCode = string(entities.CodeInsufficientPermission)
	case entities.ErrIPNotAllowed:
		statusCode = http.StatusForbidden
		message = "Access not allowed from this IP address"
		errorCode = string(entities.CodeIPNotAllowed)
	case entities.ErrTimeNotAllowed:
		statusCode = http.StatusForbidden
		message = "Access not allowed at this time"
		errorCode = string(entities.CodeTimeNotAllowed)

	// Authentication/Authorization errors
	case entities.ErrUnauthorized:
		statusCode = http.StatusUnauthorized
		message = "Unauthorized"
		errorCode = string(entities.CodeUnauthorized)
	case entities.ErrForbidden:
		statusCode = http.StatusForbidden
		message = "Forbidden"
		errorCode = string(entities.CodeForbidden)
	case entities.ErrTokenExpired:
		statusCode = http.StatusUnauthorized
		message = "Token has expired"
		errorCode = string(entities.CodeTokenExpired)
	case entities.ErrSessionExpired:
		statusCode = http.StatusUnauthorized
		message = "Session has expired"
		errorCode = string(entities.CodeSessionExpired)
	case entities.ErrMFARequired:
		statusCode = http.StatusUnauthorized
		message = "Multi-factor authentication required"
		errorCode = string(entities.CodeMFARequired)

	// Validation errors
	case entities.ErrValidationFailed:
		statusCode = http.StatusBadRequest
		message = "Validation failed"
		errorCode = string(entities.CodeValidationFailed)
	case entities.ErrInvalidInput:
		statusCode = http.StatusBadRequest
		message = "Invalid input"
		errorCode = string(entities.CodeInvalidInput)
	case entities.ErrRequiredFieldMissing:
		statusCode = http.StatusBadRequest
		message = "Required field missing"
		errorCode = string(entities.CodeRequiredFieldMissing)

	// SSH Key errors
	case entities.ErrSSHKeyNotFound:
		statusCode = http.StatusNotFound
		message = "SSH key not found"
		errorCode = "SSH_KEY_NOT_FOUND"
	case entities.ErrSSHKeyAlreadyExists:
		statusCode = http.StatusConflict
		message = "SSH key already exists"
		errorCode = "SSH_KEY_ALREADY_EXISTS"
	case entities.ErrInvalidSSHKeyContent:
		statusCode = http.StatusBadRequest
		message = "Invalid SSH key content"
		errorCode = "INVALID_SSH_KEY"

	// System errors
	case entities.ErrServiceUnavailable:
		statusCode = http.StatusServiceUnavailable
		message = "Service temporarily unavailable"
		errorCode = string(entities.CodeServiceUnavailable)
	case entities.ErrRateLimitExceeded:
		statusCode = http.StatusTooManyRequests
		message = "Rate limit exceeded"
		errorCode = string(entities.CodeRateLimitExceeded)
	case entities.ErrTimeout:
		statusCode = http.StatusRequestTimeout
		message = "Request timeout"
		errorCode = string(entities.CodeTimeout)

	default:
		// Check if it's an APIError
		if apiErr, ok := err.(*entities.APIError); ok {
			statusCode = getHTTPStatusFromErrorCode(apiErr.Code)
			message = apiErr.Message
			errorCode = string(apiErr.Code)
		} else {
			// Unknown error
			statusCode = http.StatusInternalServerError
			message = "Internal server error"
			errorCode = string(entities.CodeInternalError)
		}
	}

	response := Response{
		Success: false,
		Message: message,
		Error: &ErrorInfo{
			Code:    errorCode,
			Details: err.Error(),
		},
		Timestamp: getCurrentTimestamp(),
	}

	// Add request ID if available
	if requestID := c.GetString("request_id"); requestID != "" {
		if response.Meta == nil {
			response.Meta = &Meta{}
		}
		response.Meta.RequestID = requestID
	}

	c.JSON(statusCode, response)
}

// SuccessWithMeta sends a successful response with metadata
func SuccessWithMeta(c *gin.Context, statusCode int, message string, data interface{}, meta *Meta) {
	response := Response{
		Success:   true,
		Message:   message,
		Data:      data,
		Meta:      meta,
		Timestamp: getCurrentTimestamp(),
	}

	// Add request ID if available
	if requestID := c.GetString("request_id"); requestID != "" {
		if response.Meta == nil {
			response.Meta = &Meta{}
		}
		response.Meta.RequestID = requestID
	}

	c.JSON(statusCode, response)
}

// ErrorWithContext sends an error response with additional context
func ErrorWithContext(c *gin.Context, statusCode int, message, details string, context map[string]interface{}) {
	response := Response{
		Success: false,
		Message: message,
		Error: &ErrorInfo{
			Code:    getErrorCode(statusCode),
			Details: details,
			Context: context,
		},
		Timestamp: getCurrentTimestamp(),
	}

	// Add request ID if available
	if requestID := c.GetString("request_id"); requestID != "" {
		if response.Meta == nil {
			response.Meta = &Meta{}
		}
		response.Meta.RequestID = requestID
	}

	c.JSON(statusCode, response)
}

// NotFound sends a 404 not found response
func NotFound(c *gin.Context, resource string) {
	Error(c, http.StatusNotFound, "Resource not found", resource+" not found")
}

// Unauthorized sends a 401 unauthorized response
func Unauthorized(c *gin.Context, message string) {
	if message == "" {
		message = "Authentication required"
	}
	Error(c, http.StatusUnauthorized, message, "Please provide valid authentication credentials")
}

// Forbidden sends a 403 forbidden response
func Forbidden(c *gin.Context, message string) {
	if message == "" {
		message = "Access forbidden"
	}
	Error(c, http.StatusForbidden, message, "You don't have permission to access this resource")
}

// InternalError sends a 500 internal server error response
func InternalError(c *gin.Context, err error) {
	Error(c, http.StatusInternalServerError, "Internal server error", err.Error())
}

// Helper functions

func getCurrentTimestamp() string {
	return "2023-12-01T12:00:00Z" // In production, use time.Now().UTC().Format(time.RFC3339)
}

func getErrorCode(statusCode int) string {
	switch statusCode {
	case http.StatusBadRequest:
		return "BAD_REQUEST"
	case http.StatusUnauthorized:
		return "UNAUTHORIZED"
	case http.StatusForbidden:
		return "FORBIDDEN"
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusConflict:
		return "CONFLICT"
	case http.StatusTooManyRequests:
		return "RATE_LIMIT_EXCEEDED"
	case http.StatusInternalServerError:
		return "INTERNAL_ERROR"
	case http.StatusServiceUnavailable:
		return "SERVICE_UNAVAILABLE"
	case http.StatusRequestTimeout:
		return "TIMEOUT"
	default:
		return "UNKNOWN_ERROR"
	}
}

func getHTTPStatusFromErrorCode(code entities.ErrorCode) int {
	switch code {
	case entities.CodeUserNotFound, entities.CodeServerNotFound, entities.CodeGroupNotFound,
		entities.CodeProjectNotFound, entities.CodeAccessNotFound:
		return http.StatusNotFound
	case entities.CodeUserAlreadyExists, entities.CodeServerAlreadyExists, entities.CodeGroupAlreadyExists,
		entities.CodeProjectAlreadyExists:
		return http.StatusConflict
	case entities.CodeInvalidCredentials, entities.CodeUnauthorized, entities.CodeTokenExpired,
		entities.CodeSessionExpired, entities.CodeMFARequired:
		return http.StatusUnauthorized
	case entities.CodeUserInactive, entities.CodeUserBanned, entities.CodeServerInactive,
		entities.CodeProjectInactive, entities.CodeForbidden, entities.CodeInsufficientPermission,
		entities.CodeAccessExpired, entities.CodeAccessRevoked, entities.CodeIPNotAllowed,
		entities.CodeTimeNotAllowed:
		return http.StatusForbidden
	case entities.CodeValidationFailed, entities.CodeInvalidInput, entities.CodeRequiredFieldMissing,
		entities.CodeCircularDependency:
		return http.StatusBadRequest
	case entities.CodeServerConnectionFailed, entities.CodeServiceUnavailable:
		return http.StatusServiceUnavailable
	case entities.CodeRateLimitExceeded:
		return http.StatusTooManyRequests
	case entities.CodeTimeout:
		return http.StatusRequestTimeout
	default:
		return http.StatusInternalServerError
	}
}
