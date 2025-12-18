package types

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type UserContext struct {
	UserID      string            `json:"user_id"`
	Username    string            `json:"username"`
	Email       string            `json:"email"`
	Roles       map[string]string `json:"roles"`       // resource_id -> role
	Permissions []string          `json:"permissions"` // calculated permissions
	TokenExpiry time.Time         `json:"token_expiry"`
	Claims      jwt.MapClaims     `json:"claims"`
}

type JWTConfig struct {
	Secret         string        `json:"secret"`
	Issuer         string        `json:"issuer"`
	TokenExpiry    time.Duration `json:"token_expiry"`
	EnableCache    bool          `json:"enable_cache"`
	CacheTTL       time.Duration `json:"cache_ttl"`
	EnableFallback bool          `json:"enable_fallback"`
	AuthServiceURL string        `json:"auth_service_url"`
}

type ResourcePermission struct {
	Resource string   `json:"resource"` // "site", "page", "member"
	Action   string   `json:"action"`   // "create", "read", "update", "delete"
	Roles    []string `json:"roles"`    // roles yang bisa akses
}

type RolePermissionMatrix map[string]map[string][]string // role -> resource -> actions

// Context keys untuk passing user context
type ContextKey string

const (
	UserContextKey ContextKey = "user_context"
	UserIDKey      ContextKey = "user_id"
	RolesKey       ContextKey = "roles"
)
