package types

import (
	"time"

	"github.com/google/uuid"
)

// UserSite represents the relationship between a user and a site
type UserSite struct {
	ID        uuid.UUID `json:"id"`
	SiteID    uuid.UUID `json:"site_id"`
	UserID    uuid.UUID `json:"user_id"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy uuid.UUID `json:"created_by"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy uuid.UUID `json:"updated_by"`
}

// Site represents a site entity
type Site struct {
	ID        uuid.UUID  `json:"id"`
	UserID    uuid.UUID  `json:"user_id"`
	Host      string     `json:"host"`
	CreatedAt time.Time  `json:"created_at"`
	CreatedBy uuid.UUID  `json:"created_by"`
	UpdatedAt time.Time  `json:"updated_at"`
	UpdatedBy uuid.UUID  `json:"updated_by"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
	DeletedBy uuid.UUID  `json:"deleted_by,omitempty"`
}

// SitePage represents a site page entity
type SitePage struct {
	ID        uuid.UUID  `json:"id"`
	SiteID    uuid.UUID  `json:"site_id"`
	Page      string     `json:"page"`
	CreatedAt time.Time  `json:"created_at"`
	CreatedBy uuid.UUID  `json:"created_by"`
	UpdatedAt time.Time  `json:"updated_at"`
	UpdatedBy uuid.UUID  `json:"updated_by"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
	DeletedBy uuid.UUID  `json:"deleted_by,omitempty"`
}

// SiteAccessRequest represents a request to access a site
type SiteAccessRequest struct {
	SiteID   string `json:"site_id"`
	UserID   string `json:"user_id"`
	Role     string `json:"role,omitempty"`
	Action   string `json:"action,omitempty"`
	Resource string `json:"resource,omitempty"`
}

// SiteAccessResponse represents the response for site access validation
type SiteAccessResponse struct {
	HasAccess bool   `json:"has_access"`
	Role      string `json:"role,omitempty"`
	Message   string `json:"message,omitempty"`
}

// SitePermission represents a permission for a specific site
type SitePermission struct {
	SiteID     string     `json:"site_id"`
	UserID     string     `json:"user_id"`
	Permission string     `json:"permission"`
	GrantedAt  time.Time  `json:"granted_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// SiteRole represents a role within a site context
type SiteRole struct {
	UserID     string    `json:"user_id"`
	SiteID     string    `json:"site_id"`
	Role       string    `json:"role"`
	AssignedAt time.Time `json:"assigned_at"`
	AssignedBy string    `json:"assigned_by"`
}

// Constants for site roles
const (
	SiteRoleOwner  = "owner"
	SiteRoleAdmin  = "admin"
	SiteRoleMember = "member"
	SiteRoleViewer = "viewer"
)

// Constants for site permissions
const (
	SitePermissionRead   = "site:read"
	SitePermissionWrite  = "site:write"
	SitePermissionDelete = "site:delete"
	SitePermissionManage = "site:manage"
	SitePermissionInvite = "site:invite"

	PagePermissionRead   = "page:read"
	PagePermissionWrite  = "page:write"
	PagePermissionDelete = "page:delete"
	PagePermissionCreate = "page:create"

	MemberPermissionRead   = "member:read"
	MemberPermissionWrite  = "member:write"
	MemberPermissionDelete = "member:delete"
	MemberPermissionInvite = "member:invite"
)

// SiteRoleHierarchy defines the hierarchy of site roles
var SiteRoleHierarchy = map[string]int{
	SiteRoleOwner:  4,
	SiteRoleAdmin:  3,
	SiteRoleMember: 2,
	SiteRoleViewer: 1,
}

// RolePermissions maps roles to their default permissions
var RolePermissions = map[string][]string{
	SiteRoleOwner: {
		SitePermissionRead, SitePermissionWrite, SitePermissionDelete, SitePermissionManage, SitePermissionInvite,
		PagePermissionRead, PagePermissionWrite, PagePermissionDelete, PagePermissionCreate,
		MemberPermissionRead, MemberPermissionWrite, MemberPermissionDelete, MemberPermissionInvite,
	},
	SiteRoleAdmin: {
		SitePermissionRead, SitePermissionWrite, SitePermissionInvite,
		PagePermissionRead, PagePermissionWrite, PagePermissionDelete, PagePermissionCreate,
		MemberPermissionRead, MemberPermissionWrite, MemberPermissionInvite,
	},
	SiteRoleMember: {
		SitePermissionRead,
		PagePermissionRead, PagePermissionWrite, PagePermissionCreate,
		MemberPermissionRead,
	},
	SiteRoleViewer: {
		SitePermissionRead,
		PagePermissionRead,
		MemberPermissionRead,
	},
}

// IsValidSiteRole checks if a role is valid
func IsValidSiteRole(role string) bool {
	_, exists := SiteRoleHierarchy[role]
	return exists
}

// GetRolePermissions returns permissions for a given role
func GetRolePermissions(role string) []string {
	if permissions, exists := RolePermissions[role]; exists {
		return permissions
	}
	return []string{}
}

// HasHigherOrEqualRole checks if role1 has higher or equal privilege than role2
func HasHigherOrEqualRole(role1, role2 string) bool {
	rank1, exists1 := SiteRoleHierarchy[role1]
	rank2, exists2 := SiteRoleHierarchy[role2]

	if !exists1 || !exists2 {
		return false
	}

	return rank1 >= rank2
}

// CanPerformAction checks if a role can perform a specific action
func CanPerformAction(role, action string) bool {
	permissions := GetRolePermissions(role)
	for _, permission := range permissions {
		if permission == action {
			return true
		}
	}
	return false
}
