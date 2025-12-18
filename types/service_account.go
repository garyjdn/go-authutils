package types

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ServiceAccount represents a service account for inter-service communication
type ServiceAccount struct {
	ServiceID   string            `json:"service_id"`
	ServiceName string            `json:"service_name"`
	Permissions []string          `json:"permissions"`
	Metadata    map[string]string `json:"metadata"`
	IssuedAt    time.Time         `json:"issued_at"`
	ExpiresAt   time.Time         `json:"expires_at"`
}

// ServiceTokenClaims represents the claims in a service token
type ServiceTokenClaims struct {
	Type        string            `json:"type"` // "service_account"
	ServiceID   string            `json:"service_id"`
	ServiceName string            `json:"service_name"`
	Permissions []string          `json:"permissions"`
	Metadata    map[string]string `json:"metadata"`
	Issuer      string            `json:"iss,omitempty"`
	Subject     string            `json:"sub,omitempty"`
	Audience    []string          `json:"aud,omitempty"`
	IssuedAt    int64             `json:"iat"`
	ExpiresAt   int64             `json:"exp"`
	NotBefore   int64             `json:"nbf,omitempty"`
	ID          string            `json:"jti,omitempty"`
}

// Implement jwt.Claims interface methods
func (c *ServiceTokenClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}

func (c *ServiceTokenClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}

func (c *ServiceTokenClaims) GetNotBefore() (*jwt.NumericDate, error) {
	if c.NotBefore == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.NotBefore, 0)), nil
}

func (c *ServiceTokenClaims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

func (c *ServiceTokenClaims) GetSubject() (string, error) {
	return c.Subject, nil
}

func (c *ServiceTokenClaims) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings(c.Audience), nil
}

// PropagatedUserContext represents user context passed between services
// This is different from UserContext in auth_types.go which is for token validation
type PropagatedUserContext struct {
	UserID      string            `json:"user_id"`
	Email       string            `json:"email"`
	Username    string            `json:"username"`
	Roles       map[string]string `json:"roles"`       // resource_id -> role
	Permissions []string          `json:"permissions"` // calculated permissions
	SessionID   string            `json:"session_id"`
	RequestID   string            `json:"request_id"`
	IssuedAt    int64             `json:"issued_at"`
}

// IsValid checks if the service account is valid
func (sa *ServiceAccount) IsValid() bool {
	now := time.Now()
	return now.After(sa.IssuedAt) && now.Before(sa.ExpiresAt)
}

// HasPermission checks if the service account has the specified permission
func (sa *ServiceAccount) HasPermission(permission string) bool {
	for _, p := range sa.Permissions {
		if p == permission || p == "*" {
			return true
		}
	}
	return false
}

// ServiceAccountConfig represents configuration for service accounts
type ServiceAccountConfig struct {
	ServiceID   string        `json:"service_id"`
	ServiceName string        `json:"service_name"`
	Permissions []string      `json:"permissions"`
	TokenExpiry time.Duration `json:"token_expiry"`
	RenewBefore time.Duration `json:"renew_before"`
	Enabled     bool          `json:"enabled"`
}

// DefaultServiceAccountConfig returns default configuration for service accounts
func DefaultServiceAccountConfig() *ServiceAccountConfig {
	return &ServiceAccountConfig{
		TokenExpiry: 24 * time.Hour, // 24 hours
		RenewBefore: 1 * time.Hour,  // Renew 1 hour before expiry
		Enabled:     true,
	}
}

// Additional context keys for service communication
const (
	ServiceContextKey  ContextKey = "service_context"
	UserPropagationKey ContextKey = "user_propagation"
	ServiceTokenKey    ContextKey = "service_token"
	RequestIDKey       ContextKey = "request_id"
)
