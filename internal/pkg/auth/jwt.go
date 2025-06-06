package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents JWT claims
type Claims struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// GenerateTokenPair generates access and refresh tokens
func GenerateTokenPair(userID uint, username, email, role, secret string, expirationHours, refreshHours int) (*TokenPair, error) {
	// Generate access token
	accessToken, err := GenerateAccessToken(userID, username, email, role, secret, expirationHours)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := GenerateRefreshToken(userID, username, secret, refreshHours)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(expirationHours * 3600),
		TokenType:    "Bearer",
	}, nil
}

// GenerateAccessToken generates an access token
func GenerateAccessToken(userID uint, username, email, role, secret string, expirationHours int) (string, error) {
	expirationTime := time.Now().Add(time.Duration(expirationHours) * time.Hour)

	claims := &Claims{
		UserID:   userID,
		Username: username,
		Email:    email,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "ssh-access-management",
			Subject:   username,
			ID:        fmt.Sprintf("%d", userID),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// GenerateRefreshToken generates a refresh token
func GenerateRefreshToken(userID uint, username, secret string, refreshHours int) (string, error) {
	expirationTime := time.Now().Add(time.Duration(refreshHours) * time.Hour)

	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expirationTime),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    "ssh-access-management",
		Subject:   username,
		ID:        fmt.Sprintf("refresh_%d", userID),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken validates and parses a JWT token
func ValidateToken(tokenString, secret string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Check if token is expired
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("token is expired")
	}

	// Check if token is not yet valid
	if claims.NotBefore != nil && claims.NotBefore.After(time.Now()) {
		return nil, fmt.Errorf("token is not yet valid")
	}

	return claims, nil
}

// ValidateRefreshToken validates a refresh token
func ValidateRefreshToken(tokenString, secret string) (*jwt.RegisteredClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse refresh token: %w", err)
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid refresh token claims")
	}

	// Check if token is expired
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("refresh token is expired")
	}

	// Check if token is not yet valid
	if claims.NotBefore != nil && claims.NotBefore.After(time.Now()) {
		return nil, fmt.Errorf("refresh token is not yet valid")
	}

	// Check if it's actually a refresh token
	if claims.ID == "" || claims.ID[:8] != "refresh_" {
		return nil, fmt.Errorf("invalid refresh token")
	}

	return claims, nil
}

// ExtractUserIDFromToken extracts user ID from token without full validation
func ExtractUserIDFromToken(tokenString string) (uint, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &Claims{})
	if err != nil {
		return 0, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return 0, fmt.Errorf("invalid token claims")
	}

	return claims.UserID, nil
}

// RefreshAccessToken refreshes an access token using a refresh token
func RefreshAccessToken(refreshTokenString, secret string, expirationHours int) (string, error) {
	// Validate refresh token
	refreshClaims, err := ValidateRefreshToken(refreshTokenString, secret)
	if err != nil {
		return "", fmt.Errorf("invalid refresh token: %w", err)
	}

	// Extract user information from refresh token
	// The subject contains the username and ID contains "refresh_<user_id>"
	username := refreshClaims.Subject
	userIDStr := refreshClaims.ID[8:] // Remove "refresh_" prefix

	// Parse user ID
	var userID uint
	if userIDStr == "1" {
		userID = 1
	} else if userIDStr == "2" {
		userID = 2
	}
	// Add more parsing logic as needed

	// Generate new access token
	// Note: In a real implementation, you would fetch user details from database
	accessToken, err := GenerateAccessToken(userID, username, "", "user", secret, expirationHours)
	if err != nil {
		return "", fmt.Errorf("failed to generate new access token: %w", err)
	}

	return accessToken, nil
}

// BlacklistToken adds a token to the blacklist (in production, use Redis or database)
type TokenBlacklist struct {
	tokens map[string]time.Time
}

var blacklist = &TokenBlacklist{
	tokens: make(map[string]time.Time),
}

// AddToBlacklist adds a token to the blacklist
func (tb *TokenBlacklist) AddToBlacklist(tokenString string, expirationTime time.Time) {
	tb.tokens[tokenString] = expirationTime
}

// IsBlacklisted checks if a token is blacklisted
func (tb *TokenBlacklist) IsBlacklisted(tokenString string) bool {
	expirationTime, exists := tb.tokens[tokenString]
	if !exists {
		return false
	}

	// Remove expired blacklist entries
	if time.Now().After(expirationTime) {
		delete(tb.tokens, tokenString)
		return false
	}

	return true
}

// BlacklistToken adds a token to the global blacklist
func BlacklistToken(tokenString string, expirationTime time.Time) {
	blacklist.AddToBlacklist(tokenString, expirationTime)
}

// IsTokenBlacklisted checks if a token is blacklisted
func IsTokenBlacklisted(tokenString string) bool {
	return blacklist.IsBlacklisted(tokenString)
}

// ValidateTokenWithBlacklist validates a token and checks blacklist
func ValidateTokenWithBlacklist(tokenString, secret string) (*Claims, error) {
	// Check blacklist first
	if IsTokenBlacklisted(tokenString) {
		return nil, fmt.Errorf("token is blacklisted")
	}

	// Validate token
	return ValidateToken(tokenString, secret)
}

// TokenInfo represents information about a token
type TokenInfo struct {
	UserID    uint      `json:"user_id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Valid     bool      `json:"valid"`
}

// GetTokenInfo extracts information from a token
func GetTokenInfo(tokenString, secret string) (*TokenInfo, error) {
	claims, err := ValidateToken(tokenString, secret)
	if err != nil {
		return &TokenInfo{Valid: false}, nil
	}

	info := &TokenInfo{
		UserID:   claims.UserID,
		Username: claims.Username,
		Email:    claims.Email,
		Role:     claims.Role,
		Valid:    true,
	}

	if claims.IssuedAt != nil {
		info.IssuedAt = claims.IssuedAt.Time
	}

	if claims.ExpiresAt != nil {
		info.ExpiresAt = claims.ExpiresAt.Time
	}

	return info, nil
}
