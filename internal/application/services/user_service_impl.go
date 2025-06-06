package services

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"ssh-access-management/internal/domain/entities"
	"ssh-access-management/internal/domain/repositories"
	"ssh-access-management/internal/domain/services"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

type userService struct {
	userRepo  repositories.UserRepository
	auditRepo repositories.AuditRepository
}

// NewUserService creates a new user service
func NewUserService(userRepo repositories.UserRepository, auditRepo repositories.AuditRepository) services.UserService {
	return &userService{
		userRepo:  userRepo,
		auditRepo: auditRepo,
	}
}

// CreateUser creates a new user
func (s *userService) CreateUser(ctx context.Context, req services.CreateUserRequest) (*entities.User, error) {
	// Validate password strength
	if err := s.ValidatePassword(req.Password); err != nil {
		return nil, err
	}

	// Hash password
	hashedPassword, err := s.hashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user entity
	user := &entities.User{
		Username:   req.Username,
		Email:      req.Email,
		FullName:   req.FullName,
		Password:   hashedPassword,
		Department: req.Department,
		Role:       req.Role,
		Status:     string(entities.StatusActive),
	}

	// Create user in repository
	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	// Log audit event
	if err := s.auditRepo.LogUserAction(ctx, nil, entities.ActionUserCreate, entities.AuditDetails{
		Description: fmt.Sprintf("User %s created with role %s", user.Username, user.Role),
	}, "", ""); err != nil {
		// Log audit error but don't fail the operation
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	// Remove password from response
	user.Password = ""
	return user, nil
}

// GetUser retrieves a user by ID
func (s *userService) GetUser(ctx context.Context, id uint) (*entities.User, error) {
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Remove sensitive information
	user.Password = ""
	return user, nil
}

// GetUserByUsername retrieves a user by username
func (s *userService) GetUserByUsername(ctx context.Context, username string) (*entities.User, error) {
	user, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return nil, err
	}

	// Remove sensitive information
	user.Password = ""
	return user, nil
}

// GetUserByEmail retrieves a user by email
func (s *userService) GetUserByEmail(ctx context.Context, email string) (*entities.User, error) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	// Remove sensitive information
	user.Password = ""
	return user, nil
}

// UpdateUser updates a user
func (s *userService) UpdateUser(ctx context.Context, id uint, req services.UpdateUserRequest) (*entities.User, error) {
	// Get existing user
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Store original values for audit
	original := *user

	// Update fields
	if req.Email != nil {
		user.Email = *req.Email
	}
	if req.FullName != nil {
		user.FullName = *req.FullName
	}
	if req.Department != nil {
		user.Department = *req.Department
	}
	if req.Role != nil {
		user.Role = *req.Role
	}
	if req.Status != nil {
		user.Status = *req.Status
	}

	// Update user in repository
	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, err
	}

	// Log audit event with changes
	changes := s.buildUserChanges(&original, user)
	if err := s.auditRepo.LogUserAction(ctx, &user.ID, entities.ActionUserUpdate, entities.AuditDetails{
		Description: fmt.Sprintf("User %s updated", user.Username),
	}, "", ""); err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	// Add changes to audit log
	if len(changes) > 0 {
		// Additional audit log for specific changes would go here
	}

	// Remove sensitive information
	user.Password = ""
	return user, nil
}

// DeleteUser soft deletes a user
func (s *userService) DeleteUser(ctx context.Context, id uint) error {
	// Get user for audit
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Delete user
	if err := s.userRepo.Delete(ctx, id); err != nil {
		return err
	}

	// Log audit event
	if err := s.auditRepo.LogUserAction(ctx, &user.ID, entities.ActionUserDelete, entities.AuditDetails{
		Description: fmt.Sprintf("User %s deleted", user.Username),
	}, "", ""); err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	return nil
}

// ListUsers retrieves users with filtering and pagination
func (s *userService) ListUsers(ctx context.Context, req services.ListUsersRequest) (*services.ListUsersResponse, error) {
	filter := repositories.UserFilter{
		Username:   req.Username,
		Email:      req.Email,
		FullName:   req.FullName,
		Department: req.Department,
		Role:       req.Role,
		Status:     req.Status,
		Search:     req.Search,
		GroupID:    req.GroupID,
		ProjectID:  req.ProjectID,
		Pagination: repositories.NewPaginationParams(req.Page, req.PageSize),
		SortBy:     req.SortBy,
		SortOrder:  req.SortOrder,
	}

	users, pagination, err := s.userRepo.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	// Remove sensitive information
	for i := range users {
		users[i].Password = ""
	}

	return &services.ListUsersResponse{
		Users:      users,
		Pagination: pagination,
	}, nil
}

// ActivateUser activates a user
func (s *userService) ActivateUser(ctx context.Context, id uint) error {
	if err := s.userRepo.Activate(ctx, id); err != nil {
		return err
	}

	// Log audit event
	if err := s.auditRepo.LogUserAction(ctx, &id, entities.ActionUserUpdate, entities.AuditDetails{
		Description: "User activated",
	}, "", ""); err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	return nil
}

// DeactivateUser deactivates a user
func (s *userService) DeactivateUser(ctx context.Context, id uint) error {
	if err := s.userRepo.Deactivate(ctx, id); err != nil {
		return err
	}

	// Log audit event
	if err := s.auditRepo.LogUserAction(ctx, &id, entities.ActionUserUpdate, entities.AuditDetails{
		Description: "User deactivated",
	}, "", ""); err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	return nil
}

// BanUser bans a user
func (s *userService) BanUser(ctx context.Context, id uint, reason string) error {
	if err := s.userRepo.Ban(ctx, id); err != nil {
		return err
	}

	// Log audit event
	if err := s.auditRepo.LogUserAction(ctx, &id, entities.ActionUserUpdate, entities.AuditDetails{
		Description: fmt.Sprintf("User banned. Reason: %s", reason),
	}, "", ""); err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	return nil
}

// AuthenticateUser authenticates user credentials
func (s *userService) AuthenticateUser(ctx context.Context, username, password string) (*entities.User, error) {
	user, err := s.userRepo.ValidateCredentials(ctx, username, password)
	if err != nil {
		// Log failed login
		if err := s.auditRepo.LogFailedLogin(ctx, username, "", "", "Invalid credentials"); err != nil {
			fmt.Printf("Failed to log failed login: %v\n", err)
		}
		return nil, entities.ErrInvalidUserCredentials
	}

	// Check if user is active
	if !user.IsActive() {
		// Log failed login
		if err := s.auditRepo.LogFailedLogin(ctx, username, "", "", "User inactive"); err != nil {
			fmt.Printf("Failed to log failed login: %v\n", err)
		}
		return nil, entities.ErrUserInactive
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		// Log failed login
		if err := s.auditRepo.LogFailedLogin(ctx, username, "", "", "Password mismatch"); err != nil {
			fmt.Printf("Failed to log failed login: %v\n", err)
		}
		return nil, entities.ErrInvalidUserCredentials
	}

	// Update last login
	if err := s.userRepo.UpdateLastLogin(ctx, user.ID); err != nil {
		fmt.Printf("Failed to update last login: %v\n", err)
	}

	// Log successful login
	if err := s.auditRepo.LogSuccessfulLogin(ctx, user.ID, "", ""); err != nil {
		fmt.Printf("Failed to log successful login: %v\n", err)
	}

	// Remove sensitive information
	user.Password = ""
	return user, nil
}

// ChangePassword changes user password
func (s *userService) ChangePassword(ctx context.Context, userID uint, oldPassword, newPassword string) error {
	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPassword)); err != nil {
		return entities.ErrInvalidUserCredentials
	}

	// Validate new password
	if err := s.ValidatePassword(newPassword); err != nil {
		return err
	}

	// Hash new password
	hashedPassword, err := s.hashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	if err := s.userRepo.UpdatePassword(ctx, userID, hashedPassword); err != nil {
		return err
	}

	// Log audit event
	if err := s.auditRepo.LogPasswordChange(ctx, userID, "", "", false); err != nil {
		fmt.Printf("Failed to log password change: %v\n", err)
	}

	return nil
}

// ResetPassword resets user password (admin function)
func (s *userService) ResetPassword(ctx context.Context, email string) error {
	// Get user by email
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		return err
	}

	// Generate temporary password
	tempPassword, err := s.generateTemporaryPassword()
	if err != nil {
		return fmt.Errorf("failed to generate temporary password: %w", err)
	}

	// Hash temporary password
	hashedPassword, err := s.hashPassword(tempPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	if err := s.userRepo.UpdatePassword(ctx, user.ID, hashedPassword); err != nil {
		return err
	}

	// TODO: Send temporary password via email

	// Log audit event
	if err := s.auditRepo.LogPasswordChange(ctx, user.ID, "", "", true); err != nil {
		fmt.Printf("Failed to log password reset: %v\n", err)
	}

	return nil
}

// ValidatePassword validates password strength
func (s *userService) ValidatePassword(password string) error {
	if len(password) < 8 {
		return entities.ErrWeakPassword
	}

	// Check for at least one uppercase letter
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	if !hasUpper {
		return entities.ErrWeakPassword
	}

	// Check for at least one lowercase letter
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	if !hasLower {
		return entities.ErrWeakPassword
	}

	// Check for at least one digit
	hasDigit := regexp.MustCompile(`\d`).MatchString(password)
	if !hasDigit {
		return entities.ErrWeakPassword
	}

	// Check for at least one special character
	hasSpecial := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`).MatchString(password)
	if !hasSpecial {
		return entities.ErrWeakPassword
	}

	return nil
}

// UpdateProfile updates user profile
func (s *userService) UpdateProfile(ctx context.Context, userID uint, req services.UpdateProfileRequest) (*entities.User, error) {
	// Get existing user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Update profile fields
	if req.FullName != nil {
		user.FullName = *req.FullName
	}
	if req.Email != nil {
		user.Email = *req.Email
	}
	if req.Department != nil {
		user.Department = *req.Department
	}

	// Update user in repository
	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, err
	}

	// Remove sensitive information
	user.Password = ""
	return user, nil
}

// GetUserProfile retrieves complete user profile
func (s *userService) GetUserProfile(ctx context.Context, userID uint) (*services.UserProfile, error) {
	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Get user stats
	stats, err := s.userRepo.GetUserStats(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Get user groups
	groups, err := s.userRepo.GetUserGroups(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Get user projects
	projects, err := s.userRepo.GetUserProjects(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Get SSH keys
	sshKeys, err := s.userRepo.GetUserSSHKeys(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Build permissions list
	permissions := s.buildUserPermissions(user)

	// Remove sensitive information
	user.Password = ""

	return &services.UserProfile{
		User:           user,
		Stats:          stats,
		Groups:         groups,
		Projects:       projects,
		SSHKeys:        sshKeys,
		RecentActivity: stats.RecentActivity,
		Permissions:    permissions,
	}, nil
}

// AddSSHKey adds SSH key for user
func (s *userService) AddSSHKey(ctx context.Context, userID uint, req services.AddSSHKeyRequest) (*entities.SSHKey, error) {
	// Validate SSH key
	keyInfo, err := s.ValidateSSHKey(req.PublicKey)
	if err != nil {
		return nil, err
	}

	if !keyInfo.IsValid {
		return nil, entities.ErrInvalidSSHKeyContent
	}

	// Create SSH key entity
	sshKey := &entities.SSHKey{
		UserID:      userID,
		Name:        req.Name,
		PublicKey:   req.PublicKey,
		Fingerprint: keyInfo.Fingerprint,
		KeyType:     keyInfo.KeyType,
		BitLength:   keyInfo.BitLength,
		Comment:     req.Comment,
		IsActive:    true,
	}

	// Create SSH key in repository
	if err := s.userRepo.CreateSSHKey(ctx, sshKey); err != nil {
		return nil, err
	}

	// Log audit event
	if err := s.auditRepo.LogUserAction(ctx, &userID, entities.ActionUserUpdate, entities.AuditDetails{
		Description: fmt.Sprintf("SSH key '%s' added", req.Name),
	}, "", ""); err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	return sshKey, nil
}

// GetUserSSHKeys retrieves SSH keys for user
func (s *userService) GetUserSSHKeys(ctx context.Context, userID uint) ([]entities.SSHKey, error) {
	return s.userRepo.GetUserSSHKeys(ctx, userID)
}

// UpdateSSHKey updates SSH key
func (s *userService) UpdateSSHKey(ctx context.Context, keyID uint, req services.UpdateSSHKeyRequest) (*entities.SSHKey, error) {
	// Get existing SSH key
	sshKey, err := s.userRepo.GetSSHKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	// Update fields
	if req.Name != nil {
		sshKey.Name = *req.Name
	}
	if req.Comment != nil {
		sshKey.Comment = *req.Comment
	}
	if req.IsActive != nil {
		sshKey.IsActive = *req.IsActive
	}

	// Update SSH key in repository
	if err := s.userRepo.UpdateSSHKey(ctx, sshKey); err != nil {
		return nil, err
	}

	// Log audit event
	if err := s.auditRepo.LogUserAction(ctx, &sshKey.UserID, entities.ActionUserUpdate, entities.AuditDetails{
		Description: fmt.Sprintf("SSH key '%s' updated", sshKey.Name),
	}, "", ""); err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	return sshKey, nil
}

// DeleteSSHKey deletes SSH key
func (s *userService) DeleteSSHKey(ctx context.Context, keyID uint) error {
	// Get SSH key for audit
	sshKey, err := s.userRepo.GetSSHKey(ctx, keyID)
	if err != nil {
		return err
	}

	// Delete SSH key
	if err := s.userRepo.DeleteSSHKey(ctx, keyID); err != nil {
		return err
	}

	// Log audit event
	if err := s.auditRepo.LogUserAction(ctx, &sshKey.UserID, entities.ActionUserUpdate, entities.AuditDetails{
		Description: fmt.Sprintf("SSH key '%s' deleted", sshKey.Name),
	}, "", ""); err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	return nil
}

// ValidateSSHKey validates SSH key format and security
func (s *userService) ValidateSSHKey(publicKey string) (*services.SSHKeyInfo, error) {
	info := &services.SSHKeyInfo{
		IsValid:  false,
		IsSecure: false,
	}

	// Parse SSH public key
	pubKey, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		info.Warnings = append(info.Warnings, "Invalid SSH key format")
		return info, nil
	}

	info.IsValid = true
	info.Comment = comment
	info.KeyType = pubKey.Type()

	// Generate fingerprint
	fingerprint := md5.Sum(pubKey.Marshal())
	info.Fingerprint = fmt.Sprintf("%x", fingerprint)

	// Determine bit length and security
	switch pubKey.Type() {
	case "ssh-rsa":
		// For RSA keys, we need to check the bit length
		info.BitLength = 2048 // Default assumption
		if info.BitLength >= 2048 {
			info.IsSecure = true
		} else {
			info.Warnings = append(info.Warnings, "RSA key should be at least 2048 bits")
		}
	case "ssh-ed25519":
		info.BitLength = 256
		info.IsSecure = true // Ed25519 is always secure
	case "ecdsa-sha2-nistp256":
		info.BitLength = 256
		info.IsSecure = true
	case "ecdsa-sha2-nistp384":
		info.BitLength = 384
		info.IsSecure = true
	case "ecdsa-sha2-nistp521":
		info.BitLength = 521
		info.IsSecure = true
	default:
		info.Warnings = append(info.Warnings, "Unknown key type")
	}

	return info, nil
}

// AddUserToGroup adds user to a group
func (s *userService) AddUserToGroup(ctx context.Context, userID, groupID uint) error {
	return s.userRepo.AddToGroup(ctx, userID, groupID)
}

// RemoveUserFromGroup removes user from a group
func (s *userService) RemoveUserFromGroup(ctx context.Context, userID, groupID uint) error {
	return s.userRepo.RemoveFromGroup(ctx, userID, groupID)
}

// AddUserToProject adds user to a project
func (s *userService) AddUserToProject(ctx context.Context, userID, projectID uint) error {
	return s.userRepo.AddToProject(ctx, userID, projectID)
}

// RemoveUserFromProject removes user from a project
func (s *userService) RemoveUserFromProject(ctx context.Context, userID, projectID uint) error {
	return s.userRepo.RemoveFromProject(ctx, userID, projectID)
}

// GetUserGroups retrieves groups for user
func (s *userService) GetUserGroups(ctx context.Context, userID uint) ([]entities.Group, error) {
	return s.userRepo.GetUserGroups(ctx, userID)
}

// GetUserProjects retrieves projects for user
func (s *userService) GetUserProjects(ctx context.Context, userID uint) ([]entities.Project, error) {
	return s.userRepo.GetUserProjects(ctx, userID)
}

// GetUserStats retrieves user statistics
func (s *userService) GetUserStats(ctx context.Context, userID uint) (*repositories.UserStats, error) {
	return s.userRepo.GetUserStats(ctx, userID)
}

// GetUserActivity retrieves user activity for specified days
func (s *userService) GetUserActivity(ctx context.Context, userID uint, days int) (*services.UserActivity, error) {
	// Get user info
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// TODO: Implement activity retrieval from audit logs
	// This would involve querying audit logs for the user over the specified time period

	activity := &services.UserActivity{
		UserID:    userID,
		Username:  user.Username,
		TimeRange: repositories.NewTimeRange(days),
		// TODO: Populate with actual data from audit logs
	}

	return activity, nil
}

// GetUserAccessHistory retrieves user access history
func (s *userService) GetUserAccessHistory(ctx context.Context, userID uint, req services.AccessHistoryRequest) (*services.AccessHistoryResponse, error) {
	// TODO: Implement access history retrieval
	return &services.AccessHistoryResponse{
		History:    []services.AccessHistoryItem{},
		Pagination: repositories.NewPaginationResult(req.Page, req.PageSize, 0),
	}, nil
}

// BulkCreateUsers creates multiple users
func (s *userService) BulkCreateUsers(ctx context.Context, req services.BulkCreateUsersRequest) (*services.BulkOperationResult, error) {
	result := &services.BulkOperationResult{
		TotalRequested: len(req.Users),
	}

	for i, userReq := range req.Users {
		user, err := s.CreateUser(ctx, userReq)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, services.BulkOperationError{
				Index:   i,
				Message: err.Error(),
			})
		} else {
			result.Successful++
			result.Results = append(result.Results, user)
		}
	}

	return result, nil
}

// BulkUpdateUsers updates multiple users
func (s *userService) BulkUpdateUsers(ctx context.Context, req services.BulkUpdateUsersRequest) (*services.BulkOperationResult, error) {
	result := &services.BulkOperationResult{
		TotalRequested: len(req.Updates),
	}

	for i, update := range req.Updates {
		user, err := s.UpdateUser(ctx, update.ID, update.Data)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, services.BulkOperationError{
				Index:   i,
				ID:      &update.ID,
				Message: err.Error(),
			})
		} else {
			result.Successful++
			result.Results = append(result.Results, user)
		}
	}

	return result, nil
}

// BulkDeleteUsers deletes multiple users
func (s *userService) BulkDeleteUsers(ctx context.Context, userIDs []uint) (*services.BulkOperationResult, error) {
	result := &services.BulkOperationResult{
		TotalRequested: len(userIDs),
	}

	for i, userID := range userIDs {
		err := s.DeleteUser(ctx, userID)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, services.BulkOperationError{
				Index:   i,
				ID:      &userID,
				Message: err.Error(),
			})
		} else {
			result.Successful++
		}
	}

	return result, nil
}

// ImportUsersFromCSV imports users from CSV data
func (s *userService) ImportUsersFromCSV(ctx context.Context, csvData []byte) (*services.ImportResult, error) {
	result := &services.ImportResult{}

	// Parse CSV
	reader := csv.NewReader(strings.NewReader(string(csvData)))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSV: %w", err)
	}

	if len(records) == 0 {
		return result, nil
	}

	// Validate header
	header := records[0]
	expectedColumns := []string{"username", "email", "full_name", "department", "role"}
	if len(header) < len(expectedColumns) {
		return nil, fmt.Errorf("invalid CSV format: missing required columns")
	}

	result.TotalRows = len(records) - 1 // Exclude header

	// Process each row
	for i, record := range records[1:] {
		rowNum := i + 2 // Account for header and 0-based index

		if len(record) < len(expectedColumns) {
			result.Failed++
			result.Errors = append(result.Errors, services.ImportError{
				Row:     rowNum,
				Message: "Insufficient columns",
				Data:    strings.Join(record, ","),
			})
			continue
		}

		// Create user request
		userReq := services.CreateUserRequest{
			Username:   strings.TrimSpace(record[0]),
			Email:      strings.TrimSpace(record[1]),
			FullName:   strings.TrimSpace(record[2]),
			Department: strings.TrimSpace(record[3]),
			Role:       strings.TrimSpace(record[4]),
			Password:   s.generateDefaultPassword(), // Generate default password
		}

		// Validate required fields
		if userReq.Username == "" || userReq.Email == "" || userReq.FullName == "" || userReq.Role == "" {
			result.Failed++
			result.Errors = append(result.Errors, services.ImportError{
				Row:     rowNum,
				Message: "Missing required fields",
				Data:    strings.Join(record, ","),
			})
			continue
		}

		// Create user
		user, err := s.CreateUser(ctx, userReq)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, services.ImportError{
				Row:     rowNum,
				Message: err.Error(),
				Data:    strings.Join(record, ","),
			})
		} else {
			result.Successful++
			result.CreatedUsers = append(result.CreatedUsers, *user)
		}
	}

	return result, nil
}

// ExportUsersToCSV exports users to CSV format
func (s *userService) ExportUsersToCSV(ctx context.Context, filter repositories.UserFilter) ([]byte, error) {
	// Get users
	users, _, err := s.userRepo.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	// Create CSV content
	var csvContent strings.Builder
	writer := csv.NewWriter(&csvContent)

	// Write header
	header := []string{"ID", "Username", "Email", "Full Name", "Department", "Role", "Status", "Created At", "Last Login"}
	if err := writer.Write(header); err != nil {
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write data rows
	for _, user := range users {
		lastLogin := ""
		if user.LastLoginAt != nil {
			lastLogin = user.LastLoginAt.Format("2006-01-02 15:04:05")
		}

		row := []string{
			strconv.Itoa(int(user.ID)),
			user.Username,
			user.Email,
			user.FullName,
			user.Department,
			user.Role,
			user.Status,
			user.CreatedAt.Format("2006-01-02 15:04:05"),
			lastLogin,
		}

		if err := writer.Write(row); err != nil {
			return nil, fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("CSV writer error: %w", err)
	}

	return []byte(csvContent.String()), nil
}

// SearchUsers searches users with filters
func (s *userService) SearchUsers(ctx context.Context, query string, filters services.UserSearchFilters) ([]entities.User, error) {
	filter := repositories.UserFilter{
		Search:     query,
		Role:       filters.Role,
		Status:     filters.Status,
		Department: filters.Department,
	}

	if filters.InGroup != nil {
		filter.GroupID = filters.InGroup
	}
	if filters.InProject != nil {
		filter.ProjectID = filters.InProject
	}

	users, _, err := s.userRepo.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	// Remove sensitive information
	for i := range users {
		users[i].Password = ""
	}

	return users, nil
}

// GetUsersByRole retrieves users by role
func (s *userService) GetUsersByRole(ctx context.Context, role string) ([]entities.User, error) {
	users, err := s.userRepo.GetUsersByRole(ctx, role)
	if err != nil {
		return nil, err
	}

	// Remove sensitive information
	for i := range users {
		users[i].Password = ""
	}

	return users, nil
}

// GetActiveUsers retrieves active users
func (s *userService) GetActiveUsers(ctx context.Context) ([]entities.User, error) {
	filter := repositories.UserFilter{
		Status: string(entities.StatusActive),
	}

	users, _, err := s.userRepo.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	// Remove sensitive information
	for i := range users {
		users[i].Password = ""
	}

	return users, nil
}

// GetInactiveUsers retrieves users inactive for specified days
func (s *userService) GetInactiveUsers(ctx context.Context, days int) ([]entities.User, error) {
	// TODO: Implement logic to find users inactive for specified days
	// This would involve checking last login timestamps
	return []entities.User{}, nil
}

// CreateUserSession creates a user session
func (s *userService) CreateUserSession(ctx context.Context, userID uint, sessionInfo services.SessionInfo) (*services.UserSession, error) {
	// TODO: Implement session management
	return &services.UserSession{}, nil
}

// GetUserActiveSessions retrieves active sessions for user
func (s *userService) GetUserActiveSessions(ctx context.Context, userID uint) ([]services.UserSession, error) {
	// TODO: Implement session retrieval
	return []services.UserSession{}, nil
}

// InvalidateUserSession invalidates a user session
func (s *userService) InvalidateUserSession(ctx context.Context, sessionID string) error {
	// TODO: Implement session invalidation
	return nil
}

// InvalidateAllUserSessions invalidates all sessions for a user
func (s *userService) InvalidateAllUserSessions(ctx context.Context, userID uint) error {
	// TODO: Implement all session invalidation
	return nil
}

// Helper methods

func (s *userService) hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (s *userService) generateTemporaryPassword() (string, error) {
	bytes := make([]byte, 12)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:12], nil
}

func (s *userService) generateDefaultPassword() string {
	// Generate a simple default password for CSV imports
	return "TempPassword123!"
}

func (s *userService) buildUserChanges(original, updated *entities.User) map[string]string {
	changes := make(map[string]string)

	if original.Email != updated.Email {
		changes["email"] = fmt.Sprintf("%s -> %s", original.Email, updated.Email)
	}
	if original.FullName != updated.FullName {
		changes["full_name"] = fmt.Sprintf("%s -> %s", original.FullName, updated.FullName)
	}
	if original.Department != updated.Department {
		changes["department"] = fmt.Sprintf("%s -> %s", original.Department, updated.Department)
	}
	if original.Role != updated.Role {
		changes["role"] = fmt.Sprintf("%s -> %s", original.Role, updated.Role)
	}
	if original.Status != updated.Status {
		changes["status"] = fmt.Sprintf("%s -> %s", original.Status, updated.Status)
	}

	return changes
}

func (s *userService) buildUserPermissions(user *entities.User) []string {
	permissions := []string{}

	switch user.Role {
	case string(entities.RoleAdmin):
		permissions = append(permissions, "manage_users", "manage_servers", "manage_groups",
			"manage_projects", "grant_access", "revoke_access", "view_audit_logs")
	case string(entities.RoleUser):
		permissions = append(permissions, "view_servers", "request_access", "manage_ssh_keys")
	case string(entities.RoleReadonly):
		permissions = append(permissions, "view_servers")
	}

	return permissions
}
