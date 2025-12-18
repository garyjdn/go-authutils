package service

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gitlab.jatimprov.go.id/pharosia/auth-utils/types"
)

// ServiceAccountManager manages service account tokens and authentication
type ServiceAccountManager struct {
	jwtSecret   string
	issuer      string
	accounts    map[string]*types.ServiceAccount // service_id -> ServiceAccount
	tokenCache  map[string]*types.ServiceAccount // token -> ServiceAccount
	cacheExpiry time.Duration
	enableCache bool
}

// NewServiceAccountManager creates a new service account manager
func NewServiceAccountManager(jwtSecret, issuer string, options ...ServiceAccountOption) *ServiceAccountManager {
	config := &ServiceAccountManagerConfig{
		CacheExpiry: 1 * time.Hour,
		EnableCache: true,
	}

	for _, option := range options {
		option(config)
	}

	return &ServiceAccountManager{
		jwtSecret:   jwtSecret,
		issuer:      issuer,
		accounts:    make(map[string]*types.ServiceAccount),
		tokenCache:  make(map[string]*types.ServiceAccount),
		cacheExpiry: config.CacheExpiry,
		enableCache: config.EnableCache,
	}
}

// ServiceAccountOption configures the service account manager
type ServiceAccountOption func(*ServiceAccountManagerConfig)

type ServiceAccountManagerConfig struct {
	CacheExpiry time.Duration
	EnableCache bool
}

// WithCacheExpiry sets the cache expiry duration
func WithCacheExpiry(expiry time.Duration) ServiceAccountOption {
	return func(config *ServiceAccountManagerConfig) {
		config.CacheExpiry = expiry
	}
}

// WithCacheEnabled enables or disables caching
func WithCacheEnabled(enabled bool) ServiceAccountOption {
	return func(config *ServiceAccountManagerConfig) {
		config.EnableCache = enabled
	}
}

// RegisterServiceAccount registers a new service account
func (sam *ServiceAccountManager) RegisterServiceAccount(serviceID, serviceName string, permissions []string, metadata map[string]string) (*types.ServiceAccount, error) {
	if serviceID == "" || serviceName == "" {
		return nil, fmt.Errorf("service ID and name are required")
	}

	// Check if service account already exists
	if _, exists := sam.accounts[serviceID]; exists {
		return nil, fmt.Errorf("service account with ID %s already exists", serviceID)
	}

	// Create service account
	now := time.Now()
	serviceAccount := &types.ServiceAccount{
		ServiceID:   serviceID,
		ServiceName: serviceName,
		Permissions: permissions,
		Metadata:    metadata,
		IssuedAt:    now,
		ExpiresAt:   now.Add(24 * time.Hour), // Default 24 hours
	}

	// Store service account
	sam.accounts[serviceID] = serviceAccount

	return serviceAccount, nil
}

// GenerateServiceToken generates a JWT token for a service account
func (sam *ServiceAccountManager) GenerateServiceToken(serviceID string, expiry time.Duration) (string, error) {
	serviceAccount, exists := sam.accounts[serviceID]
	if !exists {
		return "", fmt.Errorf("service account with ID %s not found", serviceID)
	}

	// Check if service account is valid
	if !serviceAccount.IsValid() {
		return "", fmt.Errorf("service account %s is expired or invalid", serviceID)
	}

	// Calculate expiry
	now := time.Now()
	tokenExpiry := now.Add(expiry)
	if expiry == 0 {
		tokenExpiry = now.Add(1 * time.Hour) // Default 1 hour
	}

	// Create JWT claims
	claims := &types.ServiceTokenClaims{
		Type:        "service_account",
		ServiceID:   serviceAccount.ServiceID,
		ServiceName: serviceAccount.ServiceName,
		Permissions: serviceAccount.Permissions,
		Metadata:    serviceAccount.Metadata,
		Issuer:      sam.issuer,
		Subject:     serviceAccount.ServiceID,
		IssuedAt:    now.Unix(),
		ExpiresAt:   tokenExpiry.Unix(),
		ID:          GenerateRequestID(),
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(sam.jwtSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign service token: %w", err)
	}

	// Cache the token if caching is enabled
	if sam.enableCache {
		sam.tokenCache[tokenString] = serviceAccount
		// TODO: Implement cache cleanup for expired tokens
	}

	return tokenString, nil
}

// ValidateServiceToken validates a service token and returns the service account
func (sam *ServiceAccountManager) ValidateServiceToken(tokenString string) (*types.ServiceAccount, error) {
	// Check cache first
	if sam.enableCache {
		if cachedAccount, exists := sam.tokenCache[tokenString]; exists {
			if cachedAccount.IsValid() {
				return cachedAccount, nil
			}
			// Remove expired token from cache
			delete(sam.tokenCache, tokenString)
		}
	}

	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, &types.ServiceTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(sam.jwtSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse service token: %w", err)
	}

	claims, ok := token.Claims.(*types.ServiceTokenClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid service token claims")
	}

	// Verify token type
	if claims.Type != "service_account" {
		return nil, fmt.Errorf("token is not a service account token")
	}

	// Get service account
	serviceAccount, exists := sam.accounts[claims.ServiceID]
	if !exists {
		return nil, fmt.Errorf("service account %s not found", claims.ServiceID)
	}

	// Check if service account is valid
	if !serviceAccount.IsValid() {
		return nil, fmt.Errorf("service account %s is expired or invalid", claims.ServiceID)
	}

	// Cache the validated token
	if sam.enableCache {
		sam.tokenCache[tokenString] = serviceAccount
	}

	return serviceAccount, nil
}

// RevokeServiceToken revokes a service token by removing it from cache
func (sam *ServiceAccountManager) RevokeServiceToken(tokenString string) error {
	if !sam.enableCache {
		return fmt.Errorf("caching is disabled, cannot revoke token")
	}

	delete(sam.tokenCache, tokenString)
	return nil
}

// GetServiceAccount retrieves a service account by ID
func (sam *ServiceAccountManager) GetServiceAccount(serviceID string) (*types.ServiceAccount, error) {
	serviceAccount, exists := sam.accounts[serviceID]
	if !exists {
		return nil, fmt.Errorf("service account %s not found", serviceID)
	}

	return serviceAccount, nil
}

// UpdateServiceAccount updates an existing service account
func (sam *ServiceAccountManager) UpdateServiceAccount(serviceID string, updates func(*types.ServiceAccount)) error {
	serviceAccount, exists := sam.accounts[serviceID]
	if !exists {
		return fmt.Errorf("service account %s not found", serviceID)
	}

	updates(serviceAccount)

	// Clear cache for this service account
	if sam.enableCache {
		for token, account := range sam.tokenCache {
			if account.ServiceID == serviceID {
				delete(sam.tokenCache, token)
			}
		}
	}

	return nil
}

// DeleteServiceAccount removes a service account
func (sam *ServiceAccountManager) DeleteServiceAccount(serviceID string) error {
	if _, exists := sam.accounts[serviceID]; !exists {
		return fmt.Errorf("service account %s not found", serviceID)
	}

	delete(sam.accounts, serviceID)

	// Clear cache for this service account
	if sam.enableCache {
		for token, account := range sam.tokenCache {
			if account.ServiceID == serviceID {
				delete(sam.tokenCache, token)
			}
		}
	}

	return nil
}

// ListServiceAccounts returns all registered service accounts
func (sam *ServiceAccountManager) ListServiceAccounts() []*types.ServiceAccount {
	accounts := make([]*types.ServiceAccount, 0, len(sam.accounts))
	for _, account := range sam.accounts {
		accounts = append(accounts, account)
	}
	return accounts
}

// GenerateServiceID generates a unique service ID
func GenerateServiceID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// GenerateRequestID generates a unique request ID for tracing
func GenerateRequestID() string {
	return uuid.New().String()
}

// ValidateServicePermission checks if a service account has the required permission
func (sam *ServiceAccountManager) ValidateServicePermission(serviceAccount *types.ServiceAccount, requiredPermission string) bool {
	return serviceAccount.HasPermission(requiredPermission)
}
