package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// PasswordConfig represents password configuration
type PasswordConfig struct {
	MinLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireDigits    bool
	RequireSpecial   bool
	MaxLength        int
}

// DefaultPasswordConfig returns default password configuration
func DefaultPasswordConfig() *PasswordConfig {
	return &PasswordConfig{
		MinLength:        8,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireDigits:    true,
		RequireSpecial:   true,
		MaxLength:        128,
	}
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	// Use bcrypt with default cost (currently 10)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword verifies a password against its hash
func VerifyPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// ValidatePasswordStrength validates password against security requirements
func ValidatePasswordStrength(password string, config *PasswordConfig) error {
	if config == nil {
		config = DefaultPasswordConfig()
	}

	// Check minimum length
	if len(password) < config.MinLength {
		return fmt.Errorf("password must be at least %d characters long", config.MinLength)
	}

	// Check maximum length
	if config.MaxLength > 0 && len(password) > config.MaxLength {
		return fmt.Errorf("password must be at most %d characters long", config.MaxLength)
	}

	// Check for uppercase letters
	if config.RequireUppercase {
		hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
		if !hasUpper {
			return fmt.Errorf("password must contain at least one uppercase letter")
		}
	}

	// Check for lowercase letters
	if config.RequireLowercase {
		hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
		if !hasLower {
			return fmt.Errorf("password must contain at least one lowercase letter")
		}
	}

	// Check for digits
	if config.RequireDigits {
		hasDigit := regexp.MustCompile(`\d`).MatchString(password)
		if !hasDigit {
			return fmt.Errorf("password must contain at least one digit")
		}
	}

	// Check for special characters
	if config.RequireSpecial {
		hasSpecial := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~` + "`" + `]`).MatchString(password)
		if !hasSpecial {
			return fmt.Errorf("password must contain at least one special character")
		}
	}

	return nil
}

// GenerateRandomPassword generates a cryptographically secure random password
func GenerateRandomPassword(length int, includeSpecial bool) (string, error) {
	if length < 4 {
		return "", fmt.Errorf("password length must be at least 4 characters")
	}

	// Character sets
	lowercase := "abcdefghijklmnopqrstuvwxyz"
	uppercase := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits := "0123456789"
	special := "!@#$%^&*()_+-=[]{}|;:,.<>?"

	// Build character set
	charset := lowercase + uppercase + digits
	if includeSpecial {
		charset += special
	}

	// Generate password
	password := make([]byte, length)
	charsetLength := big.NewInt(int64(len(charset)))

	for i := 0; i < length; i++ {
		randomIndex, err := rand.Int(rand.Reader, charsetLength)
		if err != nil {
			return "", fmt.Errorf("failed to generate random password: %w", err)
		}
		password[i] = charset[randomIndex.Int64()]
	}

	// Ensure password meets requirements
	passwordStr := string(password)

	// Force at least one character from each required category
	if !regexp.MustCompile(`[a-z]`).MatchString(passwordStr) {
		// Replace first character with lowercase
		randomIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(lowercase))))
		password[0] = lowercase[randomIndex.Int64()]
	}

	if !regexp.MustCompile(`[A-Z]`).MatchString(passwordStr) {
		// Replace second character with uppercase
		randomIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(uppercase))))
		password[1] = uppercase[randomIndex.Int64()]
	}

	if !regexp.MustCompile(`\d`).MatchString(passwordStr) {
		// Replace third character with digit
		randomIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		password[2] = digits[randomIndex.Int64()]
	}

	if includeSpecial && !regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`+"`"+`]`).MatchString(passwordStr) {
		// Replace fourth character with special character
		if length >= 4 {
			randomIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(special))))
			password[3] = special[randomIndex.Int64()]
		}
	}

	return string(password), nil
}

// GenerateTemporaryPassword generates a temporary password for password resets
func GenerateTemporaryPassword() (string, error) {
	return GenerateRandomPassword(12, true)
}

// CheckPasswordComplexity checks password complexity and returns a score (0-100)
func CheckPasswordComplexity(password string) int {
	score := 0

	// Length score (up to 25 points)
	length := len(password)
	if length >= 8 {
		score += 10
	}
	if length >= 12 {
		score += 10
	}
	if length >= 16 {
		score += 5
	}

	// Character variety (up to 40 points)
	if regexp.MustCompile(`[a-z]`).MatchString(password) {
		score += 10
	}
	if regexp.MustCompile(`[A-Z]`).MatchString(password) {
		score += 10
	}
	if regexp.MustCompile(`\d`).MatchString(password) {
		score += 10
	}
	if regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~` + "`" + `]`).MatchString(password) {
		score += 10
	}

	// Patterns (up to 35 points)
	// No repeated characters
	if !regexp.MustCompile(`(.)\1{2,}`).MatchString(password) {
		score += 10
	}

	// No sequential characters
	if !hasSequentialChars(password) {
		score += 10
	}

	// No common words
	if !containsCommonWords(password) {
		score += 15
	}

	if score > 100 {
		score = 100
	}

	return score
}

// hasSequentialChars checks for sequential characters
func hasSequentialChars(password string) bool {
	sequential := []string{
		"123", "234", "345", "456", "567", "678", "789",
		"abc", "bcd", "cde", "def", "efg", "fgh", "ghi",
		"hij", "ijk", "jkl", "klm", "lmn", "mno", "nop",
		"opq", "pqr", "qrs", "rst", "stu", "tuv", "uvw",
		"vwx", "wxy", "xyz",
	}

	lowerPassword := strings.ToLower(password)
	for _, seq := range sequential {
		if strings.Contains(lowerPassword, seq) {
			return true
		}
	}

	return false
}

// containsCommonWords checks for common weak passwords
func containsCommonWords(password string) bool {
	commonWords := []string{
		"password", "123456", "qwerty", "admin", "root",
		"user", "guest", "test", "demo", "welcome",
		"login", "pass", "secret", "temp", "default",
	}

	lowerPassword := strings.ToLower(password)
	for _, word := range commonWords {
		if strings.Contains(lowerPassword, word) {
			return true
		}
	}

	return false
}

// GenerateSecureToken generates a cryptographically secure random token
func GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateAPIKey generates a secure API key
func GenerateAPIKey() (string, error) {
	// Generate 32 bytes (256 bits) of random data
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate API key: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// ConstantTimeEquals performs constant-time string comparison
func ConstantTimeEquals(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// HashAPIKey hashes an API key for storage
func HashAPIKey(apiKey string) (string, error) {
	return HashPassword(apiKey)
}

// VerifyAPIKey verifies an API key against its hash
func VerifyAPIKey(apiKey, hash string) error {
	return VerifyPassword(apiKey, hash)
}

// PasswordStrengthResult represents password strength analysis result
type PasswordStrengthResult struct {
	Score        int      `json:"score"`         // 0-100
	Strength     string   `json:"strength"`      // weak, fair, good, strong
	Issues       []string `json:"issues"`        // List of issues found
	Suggestions  []string `json:"suggestions"`   // List of improvement suggestions
	IsAcceptable bool     `json:"is_acceptable"` // Whether password meets minimum requirements
}

// AnalyzePasswordStrength provides comprehensive password strength analysis
func AnalyzePasswordStrength(password string, config *PasswordConfig) *PasswordStrengthResult {
	if config == nil {
		config = DefaultPasswordConfig()
	}

	result := &PasswordStrengthResult{
		Issues:      []string{},
		Suggestions: []string{},
	}

	// Calculate score
	result.Score = CheckPasswordComplexity(password)

	// Check against configuration requirements
	if err := ValidatePasswordStrength(password, config); err != nil {
		result.Issues = append(result.Issues, err.Error())
		result.IsAcceptable = false
	} else {
		result.IsAcceptable = true
	}

	// Determine strength level
	switch {
	case result.Score >= 80:
		result.Strength = "strong"
	case result.Score >= 60:
		result.Strength = "good"
	case result.Score >= 40:
		result.Strength = "fair"
	default:
		result.Strength = "weak"
	}

	// Generate suggestions
	if len(password) < 12 {
		result.Suggestions = append(result.Suggestions, "Use at least 12 characters for better security")
	}
	if !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		result.Suggestions = append(result.Suggestions, "Add uppercase letters")
	}
	if !regexp.MustCompile(`[a-z]`).MatchString(password) {
		result.Suggestions = append(result.Suggestions, "Add lowercase letters")
	}
	if !regexp.MustCompile(`\d`).MatchString(password) {
		result.Suggestions = append(result.Suggestions, "Add numbers")
	}
	if !regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~` + "`" + `]`).MatchString(password) {
		result.Suggestions = append(result.Suggestions, "Add special characters")
	}
	if hasSequentialChars(password) {
		result.Suggestions = append(result.Suggestions, "Avoid sequential characters (123, abc)")
	}
	if containsCommonWords(password) {
		result.Suggestions = append(result.Suggestions, "Avoid common words and patterns")
	}

	return result
}
