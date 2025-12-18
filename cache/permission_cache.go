package cache

import (
	"context"
	"crypto/md5"
	"fmt"
	"time"

	"github.com/patrickmn/go-cache"
	"gitlab.jatimprov.go.id/pharosia/auth-utils/types"
)

// PermissionCache provides caching for user permissions and site access
type PermissionCache struct {
	cache      *cache.Cache
	enabled    bool
	defaultTTL time.Duration
	cleanupTTL time.Duration
}

// CacheEntry represents a cached permission entry
type CacheEntry struct {
	Data      interface{} `json:"data"`
	ExpiresAt time.Time   `json:"expires_at"`
	UserID    string      `json:"user_id"`
	Resource  string      `json:"resource"`
	Action    string      `json:"action"`
}

// NewPermissionCache creates a new permission cache
func NewPermissionCache(enabled bool, defaultTTL, cleanupTTL time.Duration) *PermissionCache {
	if !enabled {
		return &PermissionCache{enabled: false}
	}

	c := cache.New(defaultTTL, cleanupTTL)

	// Start cleanup goroutine
	go func() {
		for {
			time.Sleep(cleanupTTL)
			c.DeleteExpired()
		}
	}()

	return &PermissionCache{
		cache:      c,
		enabled:    true,
		defaultTTL: defaultTTL,
		cleanupTTL: cleanupTTL,
	}
}

// IsEnabled returns true if caching is enabled
func (pc *PermissionCache) IsEnabled() bool {
	return pc.enabled
}

// CacheUserPermissions caches user permissions
func (pc *PermissionCache) CacheUserPermissions(ctx context.Context, userID string, permissions []string, ttl time.Duration) error {
	if !pc.enabled {
		return nil
	}

	key := pc.generateUserPermissionsKey(userID)

	if ttl == 0 {
		ttl = pc.defaultTTL
	}

	entry := &CacheEntry{
		Data:      permissions,
		ExpiresAt: time.Now().Add(ttl),
		UserID:    userID,
		Resource:  "user_permissions",
	}

	pc.cache.Set(key, entry, ttl)
	return nil
}

// GetUserPermissions retrieves cached user permissions
func (pc *PermissionCache) GetUserPermissions(ctx context.Context, userID string) ([]string, bool) {
	if !pc.enabled {
		return nil, false
	}

	key := pc.generateUserPermissionsKey(userID)
	if entry, found := pc.cache.Get(key); found {
		cacheEntry := entry.(*CacheEntry)
		if time.Now().Before(cacheEntry.ExpiresAt) {
			if permissions, ok := cacheEntry.Data.([]string); ok {
				return permissions, true
			}
		}
		// Remove expired entry
		pc.cache.Delete(key)
	}

	return nil, false
}

// CacheSiteAccess caches site access information
func (pc *PermissionCache) CacheSiteAccess(ctx context.Context, userID, siteID string, userSite *types.UserSite, ttl time.Duration) error {
	if !pc.enabled {
		return nil
	}

	key := pc.generateSiteAccessKey(userID, siteID)

	if ttl == 0 {
		ttl = pc.defaultTTL
	}

	entry := &CacheEntry{
		Data:      userSite,
		ExpiresAt: time.Now().Add(ttl),
		UserID:    userID,
		Resource:  "site_access",
	}

	pc.cache.Set(key, entry, ttl)
	return nil
}

// GetSiteAccess retrieves cached site access information
func (pc *PermissionCache) GetSiteAccess(ctx context.Context, userID, siteID string) (*types.UserSite, bool) {
	if !pc.enabled {
		return nil, false
	}

	key := pc.generateSiteAccessKey(userID, siteID)
	if entry, found := pc.cache.Get(key); found {
		cacheEntry := entry.(*CacheEntry)
		if time.Now().Before(cacheEntry.ExpiresAt) {
			if userSite, ok := cacheEntry.Data.(*types.UserSite); ok {
				return userSite, true
			}
		}
		// Remove expired entry
		pc.cache.Delete(key)
	}

	return nil, false
}

// CachePermissionCheck caches permission check results
func (pc *PermissionCache) CachePermissionCheck(ctx context.Context, userID, resource, action string, hasPermission bool, ttl time.Duration) error {
	if !pc.enabled {
		return nil
	}

	key := pc.generatePermissionCheckKey(userID, resource, action)

	if ttl == 0 {
		ttl = pc.defaultTTL
	}

	entry := &CacheEntry{
		Data:      hasPermission,
		ExpiresAt: time.Now().Add(ttl),
		UserID:    userID,
		Resource:  resource,
		Action:    action,
	}

	pc.cache.Set(key, entry, ttl)
	return nil
}

// GetPermissionCheck retrieves cached permission check result
func (pc *PermissionCache) GetPermissionCheck(ctx context.Context, userID, resource, action string) (bool, bool) {
	if !pc.enabled {
		return false, false
	}

	key := pc.generatePermissionCheckKey(userID, resource, action)
	if entry, found := pc.cache.Get(key); found {
		cacheEntry := entry.(*CacheEntry)
		if time.Now().Before(cacheEntry.ExpiresAt) {
			if hasPermission, ok := cacheEntry.Data.(bool); ok {
				return hasPermission, true
			}
		}
		// Remove expired entry
		pc.cache.Delete(key)
	}

	return false, false
}

// InvalidateUserPermissions removes all cached data for a user
func (pc *PermissionCache) InvalidateUserPermissions(ctx context.Context, userID string) {
	if !pc.enabled {
		return
	}

	// Get all keys for this user
	userKeys := pc.getUserKeys(userID)
	for _, key := range userKeys {
		pc.cache.Delete(key)
	}
}

// InvalidateSiteAccess removes cached site access for a specific site
func (pc *PermissionCache) InvalidateSiteAccess(ctx context.Context, siteID string) {
	if !pc.enabled {
		return
	}

	// Get all site access keys for this site
	siteKeys := pc.getSiteKeys(siteID)
	for _, key := range siteKeys {
		pc.cache.Delete(key)
	}
}

// InvalidateAll clears all cached data
func (pc *PermissionCache) InvalidateAll(ctx context.Context) {
	if !pc.enabled {
		return
	}

	pc.cache.Flush()
}

// GetCacheStats returns cache statistics
func (pc *PermissionCache) GetCacheStats() map[string]interface{} {
	if !pc.enabled {
		return map[string]interface{}{
			"enabled": false,
		}
	}

	return map[string]interface{}{
		"enabled":     true,
		"item_count":  pc.cache.ItemCount(),
		"default_ttl": pc.defaultTTL.String(),
		"cleanup_ttl": pc.cleanupTTL.String(),
	}
}

// Helper methods for key generation

func (pc *PermissionCache) generateUserPermissionsKey(userID string) string {
	return fmt.Sprintf("user_permissions:%s", userID)
}

func (pc *PermissionCache) generateSiteAccessKey(userID, siteID string) string {
	return fmt.Sprintf("site_access:%s:%s", userID, siteID)
}

func (pc *PermissionCache) generatePermissionCheckKey(userID, resource, action string) string {
	data := fmt.Sprintf("%s:%s:%s", userID, resource, action)
	hash := md5.Sum([]byte(data))
	return fmt.Sprintf("permission_check:%x", hash)
}

func (pc *PermissionCache) getUserKeys(userID string) []string {
	var keys []string

	// Get all items from cache
	for key, item := range pc.cache.Items() {
		if entry, ok := item.Object.(*CacheEntry); ok {
			if entry.UserID == userID {
				keys = append(keys, key)
			}
		}
	}

	return keys
}

func (pc *PermissionCache) getSiteKeys(siteID string) []string {
	var keys []string

	// Get all items from cache
	for key, item := range pc.cache.Items() {
		if entry, ok := item.Object.(*CacheEntry); ok {
			if entry.Resource == "site_access" {
				// Extract siteID from the cache entry or key
				if entryData, ok := entry.Data.(*types.UserSite); ok {
					if entryData.SiteID.String() == siteID {
						keys = append(keys, key)
					}
				}
			}
		}
	}

	return keys
}

// CacheManager provides high-level cache management
type CacheManager struct {
	permissionCache *PermissionCache
}

// NewCacheManager creates a new cache manager
func NewCacheManager(enabled bool, defaultTTL, cleanupTTL time.Duration) *CacheManager {
	return &CacheManager{
		permissionCache: NewPermissionCache(enabled, defaultTTL, cleanupTTL),
	}
}

// GetPermissionCache returns the permission cache
func (cm *CacheManager) GetPermissionCache() *PermissionCache {
	return cm.permissionCache
}

// CacheUser wraps user context with caching
type CachedUserContext struct {
	*types.UserContext
	CachedPermissions []string `json:"cached_permissions"`
	CacheHit          bool     `json:"cache_hit"`
}

// CacheService provides caching service for authentication and authorization
type CacheService struct {
	cache *PermissionCache
}

// NewCacheService creates a new cache service
func NewCacheService(cache *PermissionCache) *CacheService {
	return &CacheService{
		cache: cache,
	}
}

// CacheUserWithPermissions caches user context with permissions
func (cs *CacheService) CacheUserWithPermissions(ctx context.Context, userContext *types.UserContext, ttl time.Duration) error {
	if !cs.cache.IsEnabled() {
		return nil
	}

	// Cache user permissions
	return cs.cache.CacheUserPermissions(ctx, userContext.UserID, userContext.Permissions, ttl)
}

// GetUserWithCachedPermissions retrieves user context with cached permissions
func (cs *CacheService) GetUserWithCachedPermissions(ctx context.Context, userID string) (*CachedUserContext, bool) {
	if !cs.cache.IsEnabled() {
		return nil, false
	}

	permissions, cacheHit := cs.cache.GetUserPermissions(ctx, userID)
	if !cacheHit {
		return nil, false
	}

	return &CachedUserContext{
		UserContext: &types.UserContext{
			UserID:      userID,
			Permissions: permissions,
		},
		CachedPermissions: permissions,
		CacheHit:          true,
	}, true
}

// Export cache data for debugging
func (pc *PermissionCache) ExportCacheData() map[string]interface{} {
	if !pc.enabled {
		return map[string]interface{}{
			"enabled": false,
		}
	}

	data := make(map[string]interface{})
	for key, item := range pc.cache.Items() {
		if entry, ok := item.Object.(*CacheEntry); ok {
			entryData := map[string]interface{}{
				"expires_at": entry.ExpiresAt,
				"user_id":    entry.UserID,
				"resource":   entry.Resource,
				"action":     entry.Action,
			}

			// Serialize data based on type
			switch v := entry.Data.(type) {
			case []string:
				entryData["data"] = v
			case bool:
				entryData["data"] = v
			case *types.UserSite:
				entryData["data"] = map[string]interface{}{
					"user_id": v.UserID.String(),
					"site_id": v.SiteID.String(),
					"role":    v.Role,
				}
			default:
				entryData["data"] = fmt.Sprintf("%T", v)
			}

			data[key] = entryData
		}
	}

	return map[string]interface{}{
		"enabled":     true,
		"item_count":  pc.cache.ItemCount(),
		"default_ttl": pc.defaultTTL.String(),
		"cleanup_ttl": pc.cleanupTTL.String(),
		"data":        data,
	}
}
