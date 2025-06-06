package entities

import "errors"

// User related errors
var (
	ErrUserNotFound           = errors.New("user not found")
	ErrUserAlreadyExists      = errors.New("user already exists")
	ErrInvalidUserCredentials = errors.New("invalid user credentials")
	ErrUserInactive           = errors.New("user is inactive")
	ErrUserBanned             = errors.New("user is banned")
	ErrInvalidUserRole        = errors.New("invalid user role")
	ErrInvalidUserStatus      = errors.New("invalid user status")
	ErrUserNotAuthorized      = errors.New("user not authorized")
	ErrWeakPassword           = errors.New("password does not meet requirements")
	ErrPasswordMismatch       = errors.New("password confirmation does not match")
)

// Server related errors
var (
	ErrServerNotFound           = errors.New("server not found")
	ErrServerAlreadyExists      = errors.New("server already exists")
	ErrInvalidServerName        = errors.New("invalid server name")
	ErrInvalidServerIP          = errors.New("invalid server IP address")
	ErrInvalidServerEnvironment = errors.New("invalid server environment")
	ErrInvalidServerPlatform    = errors.New("invalid server platform")
	ErrInvalidServerOS          = errors.New("invalid server OS")
	ErrServerInactive           = errors.New("server is inactive")
	ErrServerBanned             = errors.New("server is banned")
	ErrServerConnectionFailed   = errors.New("failed to connect to server")
	ErrServerNotReachable       = errors.New("server is not reachable")
)

// Group related errors
var (
	ErrGroupNotFound              = errors.New("group not found")
	ErrGroupAlreadyExists         = errors.New("group already exists")
	ErrInvalidGroupName           = errors.New("invalid group name")
	ErrCircularGroupDependency    = errors.New("circular group dependency detected")
	ErrGroupInactive              = errors.New("group is inactive")
	ErrUserNotInGroup             = errors.New("user is not in group")
	ErrUserAlreadyInGroup         = errors.New("user is already in group")
	ErrServerNotInGroup           = errors.New("server is not in group")
	ErrServerAlreadyInGroup       = errors.New("server is already in group")
	ErrCannotDeleteGroupWithUsers = errors.New("cannot delete group that has users")
)

// Project related errors
var (
	ErrProjectNotFound        = errors.New("project not found")
	ErrProjectAlreadyExists   = errors.New("project already exists")
	ErrInvalidProjectName     = errors.New("invalid project name")
	ErrInvalidProjectCode     = errors.New("invalid project code")
	ErrInvalidProjectOwner    = errors.New("invalid project owner")
	ErrInvalidProjectDates    = errors.New("invalid project dates")
	ErrProjectInactive        = errors.New("project is inactive")
	ErrProjectCompleted       = errors.New("project is completed")
	ErrProjectArchived        = errors.New("project is archived")
	ErrUserNotInProject       = errors.New("user is not in project")
	ErrUserAlreadyInProject   = errors.New("user is already in project")
	ErrServerNotInProject     = errors.New("server is not in project")
	ErrServerAlreadyInProject = errors.New("server is already in project")
)

// Access related errors
var (
	ErrAccessNotFound         = errors.New("access grant not found")
	ErrAccessAlreadyExists    = errors.New("access grant already exists")
	ErrAccessExpired          = errors.New("access grant is expired")
	ErrAccessRevoked          = errors.New("access grant is revoked")
	ErrAccessInactive         = errors.New("access grant is inactive")
	ErrInvalidAccessRole      = errors.New("invalid access role")
	ErrInvalidServerID        = errors.New("invalid server ID")
	ErrInvalidGrantedBy       = errors.New("invalid granted by user")
	ErrInvalidGrantee         = errors.New("invalid grantee")
	ErrMultipleGrantees       = errors.New("multiple grantees not allowed")
	ErrInsufficientPermission = errors.New("insufficient permission")
	ErrMaxSessionsExceeded    = errors.New("maximum concurrent sessions exceeded")
	ErrSessionExpired         = errors.New("session expired")
	ErrIPNotAllowed           = errors.New("IP address not allowed")
	ErrTimeNotAllowed         = errors.New("access not allowed at this time")
	ErrCommandNotAllowed      = errors.New("command not allowed")
)

// Access Request related errors
var (
	ErrAccessRequestNotFound         = errors.New("access request not found")
	ErrAccessRequestExpired          = errors.New("access request is expired")
	ErrAccessRequestAlreadyProcessed = errors.New("access request already processed")
	ErrInvalidRequesterID            = errors.New("invalid requester ID")
	ErrInvalidReason                 = errors.New("invalid reason")
	ErrInvalidDuration               = errors.New("invalid duration")
	ErrRequestAlreadyExists          = errors.New("access request already exists")
)

// SSH Key related errors
var (
	ErrSSHKeyNotFound       = errors.New("SSH key not found")
	ErrSSHKeyAlreadyExists  = errors.New("SSH key already exists")
	ErrInvalidSSHKeyName    = errors.New("invalid SSH key name")
	ErrInvalidSSHKeyContent = errors.New("invalid SSH key content")
	ErrInvalidSSHKeyType    = errors.New("invalid SSH key type")
	ErrSSHKeyExpired        = errors.New("SSH key is expired")
	ErrSSHKeyInactive       = errors.New("SSH key is inactive")
	ErrSSHKeyFormatInvalid  = errors.New("SSH key format is invalid")
	ErrSSHKeyTooWeak        = errors.New("SSH key is too weak")
	ErrMaxSSHKeysExceeded   = errors.New("maximum SSH keys exceeded")
)

// Authentication and Authorization errors
var (
	ErrUnauthorized        = errors.New("unauthorized")
	ErrForbidden           = errors.New("forbidden")
	ErrInvalidToken        = errors.New("invalid token")
	ErrTokenExpired        = errors.New("token expired")
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrAccountLocked       = errors.New("account is locked")
	ErrMFARequired         = errors.New("multi-factor authentication required")
	ErrInvalidMFACode      = errors.New("invalid MFA code")
	ErrSessionNotFound     = errors.New("session not found")
	ErrSessionExpiredError = errors.New("session expired")
)

// Validation errors
var (
	ErrValidationFailed     = errors.New("validation failed")
	ErrInvalidInput         = errors.New("invalid input")
	ErrRequiredFieldMissing = errors.New("required field missing")
	ErrInvalidFormat        = errors.New("invalid format")
	ErrInvalidLength        = errors.New("invalid length")
	ErrInvalidCharacters    = errors.New("invalid characters")
	ErrInvalidEmail         = errors.New("invalid email format")
	ErrInvalidIPAddress     = errors.New("invalid IP address")
	ErrInvalidURL           = errors.New("invalid URL")
	ErrInvalidDateRange     = errors.New("invalid date range")
)

// Database errors
var (
	ErrDatabaseConnection   = errors.New("database connection failed")
	ErrDatabaseQuery        = errors.New("database query failed")
	ErrDatabaseTransaction  = errors.New("database transaction failed")
	ErrRecordNotFound       = errors.New("record not found")
	ErrDuplicateKey         = errors.New("duplicate key violation")
	ErrForeignKeyConstraint = errors.New("foreign key constraint violation")
	ErrCheckConstraint      = errors.New("check constraint violation")
)

// System errors
var (
	ErrInternalServer       = errors.New("internal server error")
	ErrServiceUnavailable   = errors.New("service unavailable")
	ErrTimeout              = errors.New("operation timeout")
	ErrRateLimitExceeded    = errors.New("rate limit exceeded")
	ErrResourceNotAvailable = errors.New("resource not available")
	ErrConfigurationError   = errors.New("configuration error")
	ErrExternalServiceError = errors.New("external service error")
)

// File and Network errors
var (
	ErrFileNotFound         = errors.New("file not found")
	ErrFilePermissionDenied = errors.New("file permission denied")
	ErrInvalidFileFormat    = errors.New("invalid file format")
	ErrFileSizeExceeded     = errors.New("file size exceeded")
	ErrNetworkError         = errors.New("network error")
	ErrConnectionTimeout    = errors.New("connection timeout")
	ErrConnectionRefused    = errors.New("connection refused")
)

// Business Logic errors
var (
	ErrBusinessRuleViolation = errors.New("business rule violation")
	ErrWorkflowError         = errors.New("workflow error")
	ErrStateTransitionError  = errors.New("invalid state transition")
	ErrConcurrencyError      = errors.New("concurrency error")
	ErrResourceConflict      = errors.New("resource conflict")
	ErrQuotaExceeded         = errors.New("quota exceeded")
	ErrLimitExceeded         = errors.New("limit exceeded")
)

// Audit and Compliance errors
var (
	ErrAuditLogFailed       = errors.New("failed to create audit log")
	ErrComplianceViolation  = errors.New("compliance violation")
	ErrRetentionPolicyError = errors.New("retention policy error")
	ErrDataIntegrityError   = errors.New("data integrity error")
)

// ErrorCode represents error codes for API responses
type ErrorCode string

const (
	// User error codes
	CodeUserNotFound       ErrorCode = "USER_NOT_FOUND"
	CodeUserAlreadyExists  ErrorCode = "USER_ALREADY_EXISTS"
	CodeInvalidCredentials ErrorCode = "INVALID_CREDENTIALS"
	CodeUserInactive       ErrorCode = "USER_INACTIVE"
	CodeUserBanned         ErrorCode = "USER_BANNED"

	// Server error codes
	CodeServerNotFound         ErrorCode = "SERVER_NOT_FOUND"
	CodeServerAlreadyExists    ErrorCode = "SERVER_ALREADY_EXISTS"
	CodeServerInactive         ErrorCode = "SERVER_INACTIVE"
	CodeServerConnectionFailed ErrorCode = "SERVER_CONNECTION_FAILED"

	// Group error codes
	CodeGroupNotFound      ErrorCode = "GROUP_NOT_FOUND"
	CodeGroupAlreadyExists ErrorCode = "GROUP_ALREADY_EXISTS"
	CodeCircularDependency ErrorCode = "CIRCULAR_DEPENDENCY"

	// Project error codes
	CodeProjectNotFound      ErrorCode = "PROJECT_NOT_FOUND"
	CodeProjectAlreadyExists ErrorCode = "PROJECT_ALREADY_EXISTS"
	CodeProjectInactive      ErrorCode = "PROJECT_INACTIVE"

	// Access error codes
	CodeAccessNotFound         ErrorCode = "ACCESS_NOT_FOUND"
	CodeAccessExpired          ErrorCode = "ACCESS_EXPIRED"
	CodeAccessRevoked          ErrorCode = "ACCESS_REVOKED"
	CodeInsufficientPermission ErrorCode = "INSUFFICIENT_PERMISSION"
	CodeIPNotAllowed           ErrorCode = "IP_NOT_ALLOWED"
	CodeTimeNotAllowed         ErrorCode = "TIME_NOT_ALLOWED"

	// Authentication error codes
	CodeUnauthorized   ErrorCode = "UNAUTHORIZED"
	CodeForbidden      ErrorCode = "FORBIDDEN"
	CodeTokenExpired   ErrorCode = "TOKEN_EXPIRED"
	CodeSessionExpired ErrorCode = "SESSION_EXPIRED"
	CodeMFARequired    ErrorCode = "MFA_REQUIRED"

	// Validation error codes
	CodeValidationFailed     ErrorCode = "VALIDATION_FAILED"
	CodeInvalidInput         ErrorCode = "INVALID_INPUT"
	CodeRequiredFieldMissing ErrorCode = "REQUIRED_FIELD_MISSING"

	// System error codes
	CodeInternalError      ErrorCode = "INTERNAL_ERROR"
	CodeServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"
	CodeRateLimitExceeded  ErrorCode = "RATE_LIMIT_EXCEEDED"
	CodeTimeout            ErrorCode = "TIMEOUT"
)

// APIError represents API error with code and message
type APIError struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	Details string    `json:"details,omitempty"`
}

// Error implements error interface
func (e APIError) Error() string {
	if e.Details != "" {
		return string(e.Code) + ": " + e.Message + " (" + e.Details + ")"
	}
	return string(e.Code) + ": " + e.Message
}

// NewAPIError creates a new API error
func NewAPIError(code ErrorCode, message string, details ...string) *APIError {
	err := &APIError{
		Code:    code,
		Message: message,
	}
	if len(details) > 0 {
		err.Details = details[0]
	}
	return err
}

// GetErrorCode returns error code for given error
func GetErrorCode(err error) ErrorCode {
	switch err {
	case ErrUserNotFound:
		return CodeUserNotFound
	case ErrUserAlreadyExists:
		return CodeUserAlreadyExists
	case ErrInvalidUserCredentials:
		return CodeInvalidCredentials
	case ErrUserInactive:
		return CodeUserInactive
	case ErrUserBanned:
		return CodeUserBanned
	case ErrServerNotFound:
		return CodeServerNotFound
	case ErrServerAlreadyExists:
		return CodeServerAlreadyExists
	case ErrServerInactive:
		return CodeServerInactive
	case ErrServerConnectionFailed:
		return CodeServerConnectionFailed
	case ErrGroupNotFound:
		return CodeGroupNotFound
	case ErrGroupAlreadyExists:
		return CodeGroupAlreadyExists
	case ErrCircularGroupDependency:
		return CodeCircularDependency
	case ErrProjectNotFound:
		return CodeProjectNotFound
	case ErrProjectAlreadyExists:
		return CodeProjectAlreadyExists
	case ErrProjectInactive:
		return CodeProjectInactive
	case ErrAccessNotFound:
		return CodeAccessNotFound
	case ErrAccessExpired:
		return CodeAccessExpired
	case ErrAccessRevoked:
		return CodeAccessRevoked
	case ErrInsufficientPermission:
		return CodeInsufficientPermission
	case ErrIPNotAllowed:
		return CodeIPNotAllowed
	case ErrTimeNotAllowed:
		return CodeTimeNotAllowed
	case ErrUnauthorized:
		return CodeUnauthorized
	case ErrForbidden:
		return CodeForbidden
	case ErrTokenExpired:
		return CodeTokenExpired
	case ErrSessionExpired:
		return CodeSessionExpired
	case ErrMFARequired:
		return CodeMFARequired
	case ErrValidationFailed:
		return CodeValidationFailed
	case ErrInvalidInput:
		return CodeInvalidInput
	case ErrRequiredFieldMissing:
		return CodeRequiredFieldMissing
	case ErrServiceUnavailable:
		return CodeServiceUnavailable
	case ErrRateLimitExceeded:
		return CodeRateLimitExceeded
	case ErrTimeout:
		return CodeTimeout
	default:
		return CodeInternalError
	}
}
