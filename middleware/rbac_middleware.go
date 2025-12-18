package middleware

import (
	"context"
	"fmt"
	"net/http"

	apperror "github.com/garyjdn/go-apperror"
	"github.com/garyjdn/go-authutils/types"
	"github.com/garyjdn/go-httputils"
	"github.com/go-chi/chi/v5"
)

type RolePermissionLoader interface {
	LoadUserRoles(userID string) (map[string]string, error)
}

type RBACMiddleware struct {
	permissionMatrix types.RolePermissionMatrix
	roleLoader       RolePermissionLoader
	auditLogger      types.AuditLogger
	service          string
}

func NewRBACMiddleware(service string, matrix types.RolePermissionMatrix, loader RolePermissionLoader, auditLogger types.AuditLogger) *RBACMiddleware {
	return &RBACMiddleware{
		service:          service,
		permissionMatrix: matrix,
		roleLoader:       loader,
		auditLogger:      auditLogger,
	}
}

// RequirePermission memerlukan permission tertentu
func (m *RBACMiddleware) RequirePermission(resource, action string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			userCtx, ok := GetUserContext(r)
			if !ok {
				m.logAccessEvent(ctx, "", resource, action, "", false, "no_user_context")
				httputils.WriteErrorResponse(w, apperror.ErrUnauthorized)
				return
			}

			// Load user roles jika belum ada
			if len(userCtx.Roles) == 0 && m.roleLoader != nil {
				roles, err := m.roleLoader.LoadUserRoles(userCtx.UserID)
				if err != nil {
					m.logAccessEvent(ctx, userCtx.UserID, resource, action, "", false, "failed_to_load_roles")
					httputils.WriteErrorResponse(w, apperror.NewAppError(500, "Failed to load user roles", err))
					return
				}
				userCtx.Roles = roles
			}

			// Check permission
			hasPermission := m.hasPermission(userCtx.Roles, resource, action)
			if hasPermission {
				m.logAccessEvent(ctx, userCtx.UserID, resource, action, "", true, "permission_granted")
			} else {
				m.logAccessEvent(ctx, userCtx.UserID, resource, action, "", false, "insufficient_permissions")
				httputils.WriteErrorResponse(w, apperror.ErrForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole memerlukan role tertentu pada resource tertentu
func (m *RBACMiddleware) RequireRole(resourceIDParam, requiredRole string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			userCtx, ok := GetUserContext(r)
			if !ok {
				m.logAccessEvent(ctx, "", "site", "access", "", false, "no_user_context")
				httputils.WriteErrorResponse(w, apperror.ErrUnauthorized)
				return
			}

			// Load user roles jika belum ada
			if len(userCtx.Roles) == 0 && m.roleLoader != nil {
				roles, err := m.roleLoader.LoadUserRoles(userCtx.UserID)
				if err != nil {
					m.logAccessEvent(ctx, userCtx.UserID, "site", "access", "", false, "failed_to_load_roles")
					httputils.WriteErrorResponse(w, apperror.NewAppError(500, "Failed to load user roles", err))
					return
				}
				userCtx.Roles = roles
			}

			// Get resource ID dari URL parameter
			resourceID := chi.URLParam(r, resourceIDParam)
			if resourceID == "" {
				m.logAccessEvent(ctx, userCtx.UserID, "site", "access", "", false, "missing_resource_id")
				httputils.WriteErrorResponse(w, apperror.NewAppError(400, "Resource ID required", nil))
				return
			}

			// Check user role pada resource tersebut
			userRole, exists := userCtx.Roles[resourceID]
			hasRequiredRole := m.hasRequiredRole(userRole, requiredRole)

			if exists && hasRequiredRole {
				m.logAccessEvent(ctx, userCtx.UserID, "site", "access", resourceID, true, fmt.Sprintf("role_%s_granted", userRole))
			} else {
				m.logAccessEvent(ctx, userCtx.UserID, "site", "access", resourceID, false, fmt.Sprintf("insufficient_role: required=%s, current=%s", requiredRole, userRole))
				httputils.WriteErrorResponse(w, apperror.ErrForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (m *RBACMiddleware) hasPermission(roles map[string]string, resource, action string) bool {
	for role := range roles {
		if resourcePerms, ok := m.permissionMatrix[role]; ok {
			if actions, ok := resourcePerms[resource]; ok {
				for _, allowedAction := range actions {
					if allowedAction == action || allowedAction == "*" {
						return true
					}
				}
			}
		}
	}
	return false
}

func (m *RBACMiddleware) hasRequiredRole(userRole, requiredRole string) bool {
	// Role hierarchy: owner > admin > member
	roleHierarchy := map[string]int{
		"owner":  3,
		"admin":  2,
		"member": 1,
	}

	userLevel, userExists := roleHierarchy[userRole]
	requiredLevel, requiredExists := roleHierarchy[requiredRole]

	if !userExists || !requiredExists {
		return false
	}

	return userLevel >= requiredLevel
}

// Helper methods for audit logging
func (m *RBACMiddleware) logAccessEvent(ctx context.Context, userID, resource, action, resourceID string, success bool, reason string) {
	if m.auditLogger != nil {
		m.auditLogger.LogAccessEvent(ctx, userID, resource, action, resourceID, success, reason)
	}
}
