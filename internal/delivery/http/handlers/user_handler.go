package handlers

import (
	"net/http"
	"strconv"

	"ssh-access-management/internal/delivery/http/response"
	"ssh-access-management/internal/domain/services"
	"ssh-access-management/internal/pkg/validator"

	"github.com/gin-gonic/gin"
)

type UserHandler struct {
	userService services.UserService
	validator   *validator.Validator
}

// NewUserHandler creates a new user handler
func NewUserHandler(userService services.UserService) *UserHandler {
	return &UserHandler{
		userService: userService,
		validator:   validator.New(),
	}
}

// CreateUser creates a new user
// @Summary Create a new user
// @Description Create a new user with the provided information
// @Tags users
// @Accept json
// @Produce json
// @Param user body services.CreateUserRequest true "User creation request"
// @Success 201 {object} response.Response{data=entities.User}
// @Failure 400 {object} response.Response
// @Failure 409 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/users [post]
func (h *UserHandler) CreateUser(c *gin.Context) {
	var req services.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate request
	if err := h.validator.Validate(req); err != nil {
		response.ValidationError(c, err)
		return
	}

	// Create user
	user, err := h.userService.CreateUser(c.Request.Context(), req)
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusCreated, "User created successfully", user)
}

// GetUser retrieves a user by ID
// @Summary Get user by ID
// @Description Get user information by user ID
// @Tags users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {object} response.Response{data=entities.User}
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/users/{id} [get]
func (h *UserHandler) GetUser(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid user ID", "User ID must be a valid number")
		return
	}

	user, err := h.userService.GetUser(c.Request.Context(), uint(id))
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "User retrieved successfully", user)
}

// UpdateUser updates a user
// @Summary Update user
// @Description Update user information
// @Tags users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Param user body services.UpdateUserRequest true "User update request"
// @Success 200 {object} response.Response{data=entities.User}
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 409 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/users/{id} [put]
func (h *UserHandler) UpdateUser(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid user ID", "User ID must be a valid number")
		return
	}

	var req services.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate request
	if err := h.validator.Validate(req); err != nil {
		response.ValidationError(c, err)
		return
	}

	user, err := h.userService.UpdateUser(c.Request.Context(), uint(id), req)
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "User updated successfully", user)
}

// DeleteUser deletes a user
// @Summary Delete user
// @Description Delete a user by ID
// @Tags users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/users/{id} [delete]
func (h *UserHandler) DeleteUser(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid user ID", "User ID must be a valid number")
		return
	}

	err = h.userService.DeleteUser(c.Request.Context(), uint(id))
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "User deleted successfully", nil)
}

// ListUsers retrieves users with filtering and pagination
// @Summary List users
// @Description Get a list of users with optional filtering and pagination
// @Tags users
// @Accept json
// @Produce json
// @Param username query string false "Filter by username"
// @Param email query string false "Filter by email"
// @Param full_name query string false "Filter by full name"
// @Param department query string false "Filter by department"
// @Param role query string false "Filter by role"
// @Param status query string false "Filter by status"
// @Param search query string false "Search in username, email, and full name"
// @Param group_id query int false "Filter by group ID"
// @Param project_id query int false "Filter by project ID"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Param sort_by query string false "Sort by field"
// @Param sort_order query string false "Sort order (asc/desc)" default(asc)
// @Success 200 {object} response.Response{data=services.ListUsersResponse}
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/users [get]
func (h *UserHandler) ListUsers(c *gin.Context) {
	req := services.ListUsersRequest{
		Username:   c.Query("username"),
		Email:      c.Query("email"),
		FullName:   c.Query("full_name"),
		Department: c.Query("department"),
		Role:       c.Query("role"),
		Status:     c.Query("status"),
		Search:     c.Query("search"),
		SortBy:     c.Query("sort_by"),
		SortOrder:  c.Query("sort_order"),
	}

	// Parse optional integer parameters
	if groupID := c.Query("group_id"); groupID != "" {
		if id, err := strconv.ParseUint(groupID, 10, 32); err == nil {
			gid := uint(id)
			req.GroupID = &gid
		}
	}

	if projectID := c.Query("project_id"); projectID != "" {
		if id, err := strconv.ParseUint(projectID, 10, 32); err == nil {
			pid := uint(id)
			req.ProjectID = &pid
		}
	}

	// Parse pagination parameters
	if page := c.Query("page"); page != "" {
		if p, err := strconv.Atoi(page); err == nil && p > 0 {
			req.Page = p
		}
	}
	if req.Page == 0 {
		req.Page = 1
	}

	if pageSize := c.Query("page_size"); pageSize != "" {
		if ps, err := strconv.Atoi(pageSize); err == nil && ps > 0 {
			req.PageSize = ps
		}
	}
	if req.PageSize == 0 {
		req.PageSize = 20
	}

	result, err := h.userService.ListUsers(c.Request.Context(), req)
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Users retrieved successfully", result)
}

// ActivateUser activates a user
// @Summary Activate user
// @Description Activate a user account
// @Tags users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/users/{id}/activate [post]
func (h *UserHandler) ActivateUser(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid user ID", "User ID must be a valid number")
		return
	}

	err = h.userService.ActivateUser(c.Request.Context(), uint(id))
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "User activated successfully", nil)
}

// DeactivateUser deactivates a user
// @Summary Deactivate user
// @Description Deactivate a user account
// @Tags users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/users/{id}/deactivate [post]
func (h *UserHandler) DeactivateUser(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid user ID", "User ID must be a valid number")
		return
	}

	err = h.userService.DeactivateUser(c.Request.Context(), uint(id))
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "User deactivated successfully", nil)
}

// BanUser bans a user
// @Summary Ban user
// @Description Ban a user account
// @Tags users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Param request body BanUserRequest true "Ban request"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/users/{id}/ban [post]
func (h *UserHandler) BanUser(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid user ID", "User ID must be a valid number")
		return
	}

	var req BanUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	err = h.userService.BanUser(c.Request.Context(), uint(id), req.Reason)
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "User banned successfully", nil)
}

// ChangePassword changes user password
// @Summary Change password
// @Description Change user password
// @Tags users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Param request body ChangePasswordRequest true "Password change request"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/users/{id}/change-password [post]
func (h *UserHandler) ChangePassword(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid user ID", "User ID must be a valid number")
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate request
	if err := h.validator.Validate(req); err != nil {
		response.ValidationError(c, err)
		return
	}

	err = h.userService.ChangePassword(c.Request.Context(), uint(id), req.OldPassword, req.NewPassword)
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Password changed successfully", nil)
}

// GetUserProfile retrieves user profile
// @Summary Get user profile
// @Description Get complete user profile information
// @Tags users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {object} response.Response{data=services.UserProfile}
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/users/{id}/profile [get]
func (h *UserHandler) GetUserProfile(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid user ID", "User ID must be a valid number")
		return
	}

	profile, err := h.userService.GetUserProfile(c.Request.Context(), uint(id))
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "User profile retrieved successfully", profile)
}

// UpdateUserProfile updates user profile
// @Summary Update user profile
// @Description Update user profile information
// @Tags users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Param profile body services.UpdateProfileRequest true "Profile update request"
// @Success 200 {object} response.Response{data=entities.User}
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/users/{id}/profile [put]
func (h *UserHandler) UpdateUserProfile(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid user ID", "User ID must be a valid number")
		return
	}

	var req services.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate request
	if err := h.validator.Validate(req); err != nil {
		response.ValidationError(c, err)
		return
	}

	user, err := h.userService.UpdateProfile(c.Request.Context(), uint(id), req)
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Profile updated successfully", user)
}

// AddSSHKey adds SSH key for user
// @Summary Add SSH key
// @Description Add SSH key for user
// @Tags users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Param ssh_key body services.AddSSHKeyRequest true "SSH key request"
// @Success 201 {object} response.Response{data=entities.SSHKey}
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/users/{id}/ssh-keys [post]
func (h *UserHandler) AddSSHKey(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid user ID", "User ID must be a valid number")
		return
	}

	var req services.AddSSHKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate request
	if err := h.validator.Validate(req); err != nil {
		response.ValidationError(c, err)
		return
	}

	sshKey, err := h.userService.AddSSHKey(c.Request.Context(), uint(id), req)
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusCreated, "SSH key added successfully", sshKey)
}

// GetUserSSHKeys retrieves SSH keys for user
// @Summary Get user SSH keys
// @Description Get all SSH keys for a user
// @Tags users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {object} response.Response{data=[]entities.SSHKey}
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/users/{id}/ssh-keys [get]
func (h *UserHandler) GetUserSSHKeys(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid user ID", "User ID must be a valid number")
		return
	}

	sshKeys, err := h.userService.GetUserSSHKeys(c.Request.Context(), uint(id))
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "SSH keys retrieved successfully", sshKeys)
}

// UpdateSSHKey updates SSH key
// @Summary Update SSH key
// @Description Update SSH key information
// @Tags users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Param key_id path int true "SSH Key ID"
// @Param ssh_key body services.UpdateSSHKeyRequest true "SSH key update request"
// @Success 200 {object} response.Response{data=entities.SSHKey}
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/users/{id}/ssh-keys/{key_id} [put]
func (h *UserHandler) UpdateSSHKey(c *gin.Context) {
	keyID, err := strconv.ParseUint(c.Param("key_id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid SSH key ID", "SSH key ID must be a valid number")
		return
	}

	var req services.UpdateSSHKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate request
	if err := h.validator.Validate(req); err != nil {
		response.ValidationError(c, err)
		return
	}

	sshKey, err := h.userService.UpdateSSHKey(c.Request.Context(), uint(keyID), req)
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "SSH key updated successfully", sshKey)
}

// DeleteSSHKey deletes SSH key
// @Summary Delete SSH key
// @Description Delete SSH key
// @Tags users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Param key_id path int true "SSH Key ID"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/users/{id}/ssh-keys/{key_id} [delete]
func (h *UserHandler) DeleteSSHKey(c *gin.Context) {
	keyID, err := strconv.ParseUint(c.Param("key_id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid SSH key ID", "SSH key ID must be a valid number")
		return
	}

	err = h.userService.DeleteSSHKey(c.Request.Context(), uint(keyID))
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "SSH key deleted successfully", nil)
}

// GetUserStats retrieves user statistics
// @Summary Get user statistics
// @Description Get user statistics and metrics
// @Tags users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {object} response.Response{data=repositories.UserStats}
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/users/{id}/stats [get]
func (h *UserHandler) GetUserStats(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid user ID", "User ID must be a valid number")
		return
	}

	stats, err := h.userService.GetUserStats(c.Request.Context(), uint(id))
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "User statistics retrieved successfully", stats)
}

// BulkCreateUsers creates multiple users
// @Summary Bulk create users
// @Description Create multiple users in a single request
// @Tags users
// @Accept json
// @Produce json
// @Param users body services.BulkCreateUsersRequest true "Bulk create users request"
// @Success 200 {object} response.Response{data=services.BulkOperationResult}
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/users/bulk [post]
func (h *UserHandler) BulkCreateUsers(c *gin.Context) {
	var req services.BulkCreateUsersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate request
	if err := h.validator.Validate(req); err != nil {
		response.ValidationError(c, err)
		return
	}

	result, err := h.userService.BulkCreateUsers(c.Request.Context(), req)
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Bulk user creation completed", result)
}

// SearchUsers searches users
// @Summary Search users
// @Description Search users with filters
// @Tags users
// @Accept json
// @Produce json
// @Param q query string true "Search query"
// @Param role query string false "Filter by role"
// @Param status query string false "Filter by status"
// @Param department query string false "Filter by department"
// @Success 200 {object} response.Response{data=[]entities.User}
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/users/search [get]
func (h *UserHandler) SearchUsers(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		response.Error(c, http.StatusBadRequest, "Search query is required", "Query parameter 'q' is required")
		return
	}

	filters := services.UserSearchFilters{
		Role:       c.Query("role"),
		Status:     c.Query("status"),
		Department: c.Query("department"),
	}

	users, err := h.userService.SearchUsers(c.Request.Context(), query, filters)
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Users search completed", users)
}

// Request/Response DTOs for handlers

type BanUserRequest struct {
	Reason string `json:"reason" validate:"required"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}
