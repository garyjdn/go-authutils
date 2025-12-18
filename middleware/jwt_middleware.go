package middleware

import (
	"context"
	"net/http"
	"strings"

	apperror "github.com/garyjdn/go-apperror"
	"github.com/garyjdn/go-authutils/service"
	"github.com/garyjdn/go-authutils/types"
	"github.com/garyjdn/go-httputils"
)

type JWTMiddleware struct {
	validator service.JWTValidator
}

func NewJWTMiddleware(validator service.JWTValidator) *JWTMiddleware {
	return &JWTMiddleware{
		validator: validator,
	}
}

// RequireAuthentication memerlukan valid token
func (m *JWTMiddleware) RequireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := m.extractToken(r)
		if token == "" {
			httputils.WriteErrorResponse(w, apperror.ErrUnauthorized)
			return
		}

		userCtx, err := m.validator.ValidateTokenLocally(token)
		if err != nil {
			if appErr, ok := err.(*apperror.AppError); ok {
				httputils.WriteErrorResponse(w, appErr)
			} else {
				httputils.WriteErrorResponse(w, apperror.ErrUnauthorized)
			}
			return
		}

		// Set user context di request
		ctx := context.WithValue(r.Context(), types.UserContextKey, userCtx)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// OptionalAuthentication tidak error jika tidak ada token
func (m *JWTMiddleware) OptionalAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := m.extractToken(r)
		if token != "" {
			userCtx, err := m.validator.ValidateTokenLocally(token)
			if err == nil {
				ctx := context.WithValue(r.Context(), types.UserContextKey, userCtx)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		// Lanjutkan tanpa user context
		next.ServeHTTP(w, r)
	})
}

func (m *JWTMiddleware) extractToken(r *http.Request) string {
	// Coba dari Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && parts[0] == "Bearer" {
			return parts[1]
		}
	}

	// Fallback ke cookie atau query param jika needed
	return ""
}

// Helper function untuk mendapatkan user context dari request
func GetUserContext(r *http.Request) (*types.UserContext, bool) {
	userCtx, ok := r.Context().Value(types.UserContextKey).(*types.UserContext)
	return userCtx, ok
}

// Helper function untuk mendapatkan user ID dari request
func GetUserID(r *http.Request) (string, bool) {
	userCtx, ok := GetUserContext(r)
	if !ok {
		return "", false
	}
	return userCtx.UserID, true
}
