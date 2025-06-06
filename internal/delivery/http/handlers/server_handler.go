package handlers

import (
	"net/http"
	"strconv"

	"ssh-access-management/internal/delivery/http/response"
	"ssh-access-management/internal/domain/services"
	"ssh-access-management/internal/pkg/validator"

	"github.com/gin-gonic/gin"
)

type ServerHandler struct {
	serverService services.ServerService
	validator     *validator.Validator
}

// NewServerHandler creates a new server handler
func NewServerHandler(serverService services.ServerService) *ServerHandler {
	return &ServerHandler{
		serverService: serverService,
		validator:     validator.New(),
	}
}

// CreateServer creates a new server
// @Summary Create a new server
// @Description Create a new server with the provided information
// @Tags servers
// @Accept json
// @Produce json
// @Param server body services.CreateServerRequest true "Server creation request"
// @Success 201 {object} response.Response{data=entities.Server}
// @Failure 400 {object} response.Response
// @Failure 409 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/servers [post]
func (h *ServerHandler) CreateServer(c *gin.Context) {
	var req services.CreateServerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate request
	if err := h.validator.Validate(req); err != nil {
		response.ValidationError(c, err)
		return
	}

	// Create server
	server, err := h.serverService.CreateServer(c.Request.Context(), req)
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusCreated, "Server created successfully", server)
}

// GetServer retrieves a server by ID
// @Summary Get server by ID
// @Description Get server information by server ID
// @Tags servers
// @Accept json
// @Produce json
// @Param id path int true "Server ID"
// @Success 200 {object} response.Response{data=entities.Server}
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/servers/{id} [get]
func (h *ServerHandler) GetServer(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid server ID", "Server ID must be a valid number")
		return
	}

	server, err := h.serverService.GetServer(c.Request.Context(), uint(id))
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Server retrieved successfully", server)
}

// UpdateServer updates a server
// @Summary Update server
// @Description Update server information
// @Tags servers
// @Accept json
// @Produce json
// @Param id path int true "Server ID"
// @Param server body services.UpdateServerRequest true "Server update request"
// @Success 200 {object} response.Response{data=entities.Server}
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 409 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/servers/{id} [put]
func (h *ServerHandler) UpdateServer(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid server ID", "Server ID must be a valid number")
		return
	}

	var req services.UpdateServerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate request
	if err := h.validator.Validate(req); err != nil {
		response.ValidationError(c, err)
		return
	}

	server, err := h.serverService.UpdateServer(c.Request.Context(), uint(id), req)
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Server updated successfully", server)
}

// DeleteServer deletes a server
// @Summary Delete server
// @Description Delete a server by ID
// @Tags servers
// @Accept json
// @Produce json
// @Param id path int true "Server ID"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/servers/{id} [delete]
func (h *ServerHandler) DeleteServer(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid server ID", "Server ID must be a valid number")
		return
	}

	err = h.serverService.DeleteServer(c.Request.Context(), uint(id))
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Server deleted successfully", nil)
}

// ListServers retrieves servers with filtering and pagination
// @Summary List servers
// @Description Get a list of servers with optional filtering and pagination
// @Tags servers
// @Accept json
// @Produce json
// @Param name query string false "Filter by name"
// @Param ip query string false "Filter by IP address"
// @Param hostname query string false "Filter by hostname"
// @Param environment query string false "Filter by environment"
// @Param platform query string false "Filter by platform"
// @Param os query string false "Filter by OS"
// @Param status query string false "Filter by status"
// @Param tag query string false "Filter by tag"
// @Param region query string false "Filter by region"
// @Param search query string false "Search in name, IP, hostname, and description"
// @Param group_id query int false "Filter by group ID"
// @Param project_id query int false "Filter by project ID"
// @Param is_active query bool false "Filter by active status"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Param sort_by query string false "Sort by field"
// @Param sort_order query string false "Sort order (asc/desc)" default(asc)
// @Success 200 {object} response.Response{data=services.ListServersResponse}
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/servers [get]
func (h *ServerHandler) ListServers(c *gin.Context) {
	req := services.ListServersRequest{
		Name:        c.Query("name"),
		IP:          c.Query("ip"),
		Hostname:    c.Query("hostname"),
		Environment: c.Query("environment"),
		Platform:    c.Query("platform"),
		OS:          c.Query("os"),
		Status:      c.Query("status"),
		Tag:         c.Query("tag"),
		Region:      c.Query("region"),
		Search:      c.Query("search"),
		SortBy:      c.Query("sort_by"),
		SortOrder:   c.Query("sort_order"),
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

	// Parse boolean parameter
	if isActiveStr := c.Query("is_active"); isActiveStr != "" {
		if isActive, err := strconv.ParseBool(isActiveStr); err == nil {
			req.IsActive = &isActive
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

	result, err := h.serverService.ListServers(c.Request.Context(), req)
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Servers retrieved successfully", result)
}

// ActivateServer activates a server
// @Summary Activate server
// @Description Activate a server
// @Tags servers
// @Accept json
// @Produce json
// @Param id path int true "Server ID"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/servers/{id}/activate [post]
func (h *ServerHandler) ActivateServer(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid server ID", "Server ID must be a valid number")
		return
	}

	err = h.serverService.ActivateServer(c.Request.Context(), uint(id))
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Server activated successfully", nil)
}

// DeactivateServer deactivates a server
// @Summary Deactivate server
// @Description Deactivate a server
// @Tags servers
// @Accept json
// @Produce json
// @Param id path int true "Server ID"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/servers/{id}/deactivate [post]
func (h *ServerHandler) DeactivateServer(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid server ID", "Server ID must be a valid number")
		return
	}

	err = h.serverService.DeactivateServer(c.Request.Context(), uint(id))
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Server deactivated successfully", nil)
}

// TestServerConnectivity tests server connectivity
// @Summary Test server connectivity
// @Description Test connectivity to a server
// @Tags servers
// @Accept json
// @Produce json
// @Param id path int true "Server ID"
// @Success 200 {object} response.Response{data=repositories.ServerConnectivity}
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/servers/{id}/test-connectivity [post]
func (h *ServerHandler) TestServerConnectivity(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid server ID", "Server ID must be a valid number")
		return
	}

	connectivity, err := h.serverService.TestServerConnectivity(c.Request.Context(), uint(id))
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Connectivity test completed", connectivity)
}

// GetServerStats retrieves server statistics
// @Summary Get server statistics
// @Description Get server statistics and metrics
// @Tags servers
// @Accept json
// @Produce json
// @Param id path int true "Server ID"
// @Success 200 {object} response.Response{data=repositories.ServerStats}
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/servers/{id}/stats [get]
func (h *ServerHandler) GetServerStats(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid server ID", "Server ID must be a valid number")
		return
	}

	stats, err := h.serverService.GetServerStats(c.Request.Context(), uint(id))
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Server statistics retrieved successfully", stats)
}

// AddServerTags adds tags to a server
// @Summary Add server tags
// @Description Add tags to a server
// @Tags servers
// @Accept json
// @Produce json
// @Param id path int true "Server ID"
// @Param tags body AddTagsRequest true "Tags to add"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/servers/{id}/tags [post]
func (h *ServerHandler) AddServerTags(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid server ID", "Server ID must be a valid number")
		return
	}

	var req AddTagsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	err = h.serverService.AddServerTags(c.Request.Context(), uint(id), req.Tags)
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Tags added successfully", nil)
}

// RemoveServerTags removes tags from a server
// @Summary Remove server tags
// @Description Remove tags from a server
// @Tags servers
// @Accept json
// @Produce json
// @Param id path int true "Server ID"
// @Param tags body RemoveTagsRequest true "Tags to remove"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/servers/{id}/tags [delete]
func (h *ServerHandler) RemoveServerTags(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid server ID", "Server ID must be a valid number")
		return
	}

	var req RemoveTagsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	err = h.serverService.RemoveServerTags(c.Request.Context(), uint(id), req.Tags)
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Tags removed successfully", nil)
}

// GetPlatformSummary retrieves platform summary
// @Summary Get platform summary
// @Description Get summary of servers by platform
// @Tags servers
// @Accept json
// @Produce json
// @Success 200 {object} response.Response{data=[]repositories.PlatformSummary}
// @Failure 500 {object} response.Response
// @Router /api/servers/platforms/summary [get]
func (h *ServerHandler) GetPlatformSummary(c *gin.Context) {
	summary, err := h.serverService.GetPlatformSummary(c.Request.Context())
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Platform summary retrieved successfully", summary)
}

// GetEnvironmentSummary retrieves environment summary
// @Summary Get environment summary
// @Description Get summary of servers by environment
// @Tags servers
// @Accept json
// @Produce json
// @Success 200 {object} response.Response{data=[]repositories.EnvironmentSummary}
// @Failure 500 {object} response.Response
// @Router /api/servers/environments/summary [get]
func (h *ServerHandler) GetEnvironmentSummary(c *gin.Context) {
	summary, err := h.serverService.GetEnvironmentSummary(c.Request.Context())
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Environment summary retrieved successfully", summary)
}

// GetAllTags retrieves all server tags
// @Summary Get all tags
// @Description Get all available server tags
// @Tags servers
// @Accept json
// @Produce json
// @Success 200 {object} response.Response{data=[]services.TagInfo}
// @Failure 500 {object} response.Response
// @Router /api/servers/tags [get]
func (h *ServerHandler) GetAllTags(c *gin.Context) {
	tags, err := h.serverService.GetAllTags(c.Request.Context())
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Tags retrieved successfully", tags)
}

// SearchServers searches servers
// @Summary Search servers
// @Description Search servers with filters
// @Tags servers
// @Accept json
// @Produce json
// @Param q query string true "Search query"
// @Param platform query string false "Filter by platform"
// @Param environment query string false "Filter by environment"
// @Param os query string false "Filter by OS"
// @Param status query string false "Filter by status"
// @Param region query string false "Filter by region"
// @Success 200 {object} response.Response{data=[]entities.Server}
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/servers/search [get]
func (h *ServerHandler) SearchServers(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		response.Error(c, http.StatusBadRequest, "Search query is required", "Query parameter 'q' is required")
		return
	}

	filters := services.ServerSearchFilters{
		Platform:    c.Query("platform"),
		Environment: c.Query("environment"),
		OS:          c.Query("os"),
		Status:      c.Query("status"),
		Region:      c.Query("region"),
	}

	servers, err := h.serverService.SearchServers(c.Request.Context(), query, filters)
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Server search completed", servers)
}

// GetServerAccess retrieves server access information
// @Summary Get server access
// @Description Get access information for a server
// @Tags servers
// @Accept json
// @Produce json
// @Param id path int true "Server ID"
// @Success 200 {object} response.Response{data=[]entities.AccessGrant}
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/servers/{id}/access [get]
func (h *ServerHandler) GetServerAccess(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid server ID", "Server ID must be a valid number")
		return
	}

	access, err := h.serverService.GetServerAccess(c.Request.Context(), uint(id))
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Server access retrieved successfully", access)
}

// GetServerUsers retrieves users with access to a server
// @Summary Get server users
// @Description Get users with access to a server
// @Tags servers
// @Accept json
// @Produce json
// @Param id path int true "Server ID"
// @Success 200 {object} response.Response{data=[]services.ServerUserInfo}
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/servers/{id}/users [get]
func (h *ServerHandler) GetServerUsers(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid server ID", "Server ID must be a valid number")
		return
	}

	users, err := h.serverService.GetServerUsers(c.Request.Context(), uint(id))
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Server users retrieved successfully", users)
}

// BulkCreateServers creates multiple servers
// @Summary Bulk create servers
// @Description Create multiple servers in a single request
// @Tags servers
// @Accept json
// @Produce json
// @Param servers body services.BulkCreateServersRequest true "Bulk create servers request"
// @Success 200 {object} response.Response{data=services.BulkOperationResult}
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/servers/bulk [post]
func (h *ServerHandler) BulkCreateServers(c *gin.Context) {
	var req services.BulkCreateServersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate request
	if err := h.validator.Validate(req); err != nil {
		response.ValidationError(c, err)
		return
	}

	result, err := h.serverService.BulkCreateServers(c.Request.Context(), req)
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Bulk server creation completed", result)
}

// GetServerDistribution retrieves server distribution
// @Summary Get server distribution
// @Description Get distribution of servers across platforms, environments, etc.
// @Tags servers
// @Accept json
// @Produce json
// @Success 200 {object} response.Response{data=services.ServerDistribution}
// @Failure 500 {object} response.Response
// @Router /api/servers/distribution [get]
func (h *ServerHandler) GetServerDistribution(c *gin.Context) {
	distribution, err := h.serverService.GetServerDistribution(c.Request.Context())
	if err != nil {
		response.HandleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "Server distribution retrieved successfully", distribution)
}

// GetPlatforms retrieves available platforms
// @Summary Get platforms
// @Description Get list of available platforms
// @Tags servers
// @Accept json
// @Produce json
// @Success 200 {object} response.Response{data=[]string}
// @Router /api/platforms [get]
func (h *ServerHandler) GetPlatforms(c *gin.Context) {
	platforms := []string{"vsphere", "aws", "azure"}
	response.Success(c, http.StatusOK, "Platforms retrieved successfully", platforms)
}

// Request/Response DTOs for handlers

type AddTagsRequest struct {
	Tags []string `json:"tags" validate:"required,min=1"`
}

type RemoveTagsRequest struct {
	Tags []string `json:"tags" validate:"required,min=1"`
}
