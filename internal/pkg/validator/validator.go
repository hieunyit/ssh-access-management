package validator

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
)

// Validator wraps go-playground validator
type Validator struct {
	validator *validator.Validate
}

// New creates a new validator instance
func New() *Validator {
	v := validator.New()

	// Register custom validations
	v.RegisterValidation("platform", validatePlatform)
	v.RegisterValidation("environment", validateEnvironment)
	v.RegisterValidation("server_status", validateServerStatus)
	v.RegisterValidation("user_role", validateUserRole)
	v.RegisterValidation("user_status", validateUserStatus)
	v.RegisterValidation("access_role", validateAccessRole)
	v.RegisterValidation("ssh_key_type", validateSSHKeyType)
	v.RegisterValidation("strong_password", validateStrongPassword)

	// Register tag name function to use JSON tags
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})

	return &Validator{validator: v}
}

// Validate validates a struct
func (v *Validator) Validate(s interface{}) error {
	return v.validator.Struct(s)
}

// ValidateVar validates a single variable
func (v *Validator) ValidateVar(field interface{}, tag string) error {
	return v.validator.Var(field, tag)
}

// Custom validation functions

// validatePlatform validates server platform
func validatePlatform(fl validator.FieldLevel) bool {
	platform := fl.Field().String()
	validPlatforms := []string{"vsphere", "aws", "azure"}

	for _, valid := range validPlatforms {
		if platform == valid {
			return true
		}
	}
	return false
}

// validateEnvironment validates server environment
func validateEnvironment(fl validator.FieldLevel) bool {
	environment := fl.Field().String()
	validEnvironments := []string{"production", "staging", "dev", "test"}

	for _, valid := range validEnvironments {
		if environment == valid {
			return true
		}
	}
	return false
}

// validateServerStatus validates server status
func validateServerStatus(fl validator.FieldLevel) bool {
	status := fl.Field().String()
	validStatuses := []string{"active", "inactive", "banned"}

	for _, valid := range validStatuses {
		if status == valid {
			return true
		}
	}
	return false
}

// validateUserRole validates user role
func validateUserRole(fl validator.FieldLevel) bool {
	role := fl.Field().String()
	validRoles := []string{"admin", "user", "readonly"}

	for _, valid := range validRoles {
		if role == valid {
			return true
		}
	}
	return false
}

// validateUserStatus validates user status
func validateUserStatus(fl validator.FieldLevel) bool {
	status := fl.Field().String()
	validStatuses := []string{"active", "inactive", "banned"}

	for _, valid := range validStatuses {
		if status == valid {
			return true
		}
	}
	return false
}

// validateAccessRole validates access role
func validateAccessRole(fl validator.FieldLevel) bool {
	role := fl.Field().String()
	validRoles := []string{"readonly", "user", "admin", "custom"}

	for _, valid := range validRoles {
		if role == valid {
			return true
		}
	}
	return false
}

// validateSSHKeyType validates SSH key type
func validateSSHKeyType(fl validator.FieldLevel) bool {
	keyType := fl.Field().String()
	validTypes := []string{"rsa", "ed25519", "ecdsa", "dsa"}

	for _, valid := range validTypes {
		if keyType == valid {
			return true
		}
	}
	return false
}

// validateStrongPassword validates password strength
func validateStrongPassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	// Minimum 8 characters
	if len(password) < 8 {
		return false
	}

	// At least one uppercase letter
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	if !hasUpper {
		return false
	}

	// At least one lowercase letter
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	if !hasLower {
		return false
	}

	// At least one digit
	hasDigit := regexp.MustCompile(`\d`).MatchString(password)
	if !hasDigit {
		return false
	}

	// At least one special character
	hasSpecial := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`).MatchString(password)
	if !hasSpecial {
		return false
	}

	return true
}

// ValidationError represents a validation error with field details
type ValidationError struct {
	Field   string `json:"field"`
	Value   string `json:"value"`
	Tag     string `json:"tag"`
	Message string `json:"message"`
}

// GetValidationErrors extracts validation errors with details
func (v *Validator) GetValidationErrors(err error) []ValidationError {
	var validationErrors []ValidationError

	if validationErrs, ok := err.(validator.ValidationErrors); ok {
		for _, validationErr := range validationErrs {
			field := strings.ToLower(validationErr.Field())
			tag := validationErr.Tag()
			value := fmt.Sprintf("%v", validationErr.Value())

			message := getErrorMessage(field, tag, validationErr.Param())

			validationErrors = append(validationErrors, ValidationError{
				Field:   field,
				Value:   value,
				Tag:     tag,
				Message: message,
			})
		}
	}

	return validationErrors
}

// getErrorMessage returns a human-readable error message
func getErrorMessage(field, tag, param string) string {
	switch tag {
	case "required":
		return fmt.Sprintf("%s is required", field)
	case "email":
		return fmt.Sprintf("%s must be a valid email address", field)
	case "min":
		return fmt.Sprintf("%s must be at least %s characters long", field, param)
	case "max":
		return fmt.Sprintf("%s must be at most %s characters long", field, param)
	case "len":
		return fmt.Sprintf("%s must be exactly %s characters long", field, param)
	case "ip":
		return fmt.Sprintf("%s must be a valid IP address", field)
	case "url":
		return fmt.Sprintf("%s must be a valid URL", field)
	case "uuid":
		return fmt.Sprintf("%s must be a valid UUID", field)
	case "oneof":
		return fmt.Sprintf("%s must be one of: %s", field, param)
	case "platform":
		return fmt.Sprintf("%s must be one of: vsphere, aws, azure", field)
	case "environment":
		return fmt.Sprintf("%s must be one of: production, staging, dev, test", field)
	case "server_status":
		return fmt.Sprintf("%s must be one of: active, inactive, banned", field)
	case "user_role":
		return fmt.Sprintf("%s must be one of: admin, user, readonly", field)
	case "user_status":
		return fmt.Sprintf("%s must be one of: active, inactive, banned", field)
	case "access_role":
		return fmt.Sprintf("%s must be one of: readonly, user, admin, custom", field)
	case "ssh_key_type":
		return fmt.Sprintf("%s must be one of: rsa, ed25519, ecdsa, dsa", field)
	case "strong_password":
		return fmt.Sprintf("%s must contain at least 8 characters with uppercase, lowercase, digit, and special character", field)
	case "gte":
		return fmt.Sprintf("%s must be greater than or equal to %s", field, param)
	case "lte":
		return fmt.Sprintf("%s must be less than or equal to %s", field, param)
	case "gt":
		return fmt.Sprintf("%s must be greater than %s", field, param)
	case "lt":
		return fmt.Sprintf("%s must be less than %s", field, param)
	case "eqfield":
		return fmt.Sprintf("%s must be equal to %s", field, param)
	case "nefield":
		return fmt.Sprintf("%s must not be equal to %s", field, param)
	case "alphanum":
		return fmt.Sprintf("%s must contain only alphanumeric characters", field)
	case "alpha":
		return fmt.Sprintf("%s must contain only letters", field)
	case "numeric":
		return fmt.Sprintf("%s must contain only numbers", field)
	default:
		return fmt.Sprintf("%s is invalid", field)
	}
}

// ValidateStruct validates a struct and returns detailed errors
func ValidateStruct(s interface{}) map[string]string {
	validator := New()
	err := validator.Validate(s)

	if err == nil {
		return nil
	}

	errors := make(map[string]string)
	validationErrors := validator.GetValidationErrors(err)

	for _, validationError := range validationErrors {
		errors[validationError.Field] = validationError.Message
	}

	return errors
}

// ValidateEmail validates email format
func ValidateEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// ValidateIP validates IP address format
func ValidateIP(ip string) bool {
	ipRegex := regexp.MustCompile(`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	return ipRegex.MatchString(ip)
}

// ValidateIPv6 validates IPv6 address format
func ValidateIPv6(ip string) bool {
	ipv6Regex := regexp.MustCompile(`^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$`)
	return ipv6Regex.MatchString(ip)
}

// ValidateUsername validates username format
func ValidateUsername(username string) bool {
	// Username must be 3-50 characters, alphanumeric with dots, hyphens, underscores
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9._-]{3,50}$`)
	return usernameRegex.MatchString(username)
}

// ValidateHostname validates hostname format
func ValidateHostname(hostname string) bool {
	// Hostname validation according to RFC 1123
	hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	return len(hostname) <= 253 && hostnameRegex.MatchString(hostname)
}

// ValidatePort validates port number
func ValidatePort(port int) bool {
	return port > 0 && port <= 65535
}

// ValidateSSHPublicKey validates SSH public key format
func ValidateSSHPublicKey(publicKey string) bool {
	// Basic SSH public key format validation
	sshKeyRegex := regexp.MustCompile(`^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)\s+[A-Za-z0-9+/]+[=]{0,3}(\s+.*)?$`)
	return sshKeyRegex.MatchString(strings.TrimSpace(publicKey))
}

// IsRequired checks if a validation error is for a required field
func IsRequired(err error) bool {
	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		for _, validationError := range validationErrors {
			if validationError.Tag() == "required" {
				return true
			}
		}
	}
	return false
}

// HasValidationTag checks if a struct field has a specific validation tag
func HasValidationTag(s interface{}, fieldName, tag string) bool {
	rv := reflect.ValueOf(s)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}

	if rv.Kind() != reflect.Struct {
		return false
	}

	field, found := rv.Type().FieldByName(fieldName)
	if !found {
		return false
	}

	validateTag := field.Tag.Get("validate")
	return strings.Contains(validateTag, tag)
}
