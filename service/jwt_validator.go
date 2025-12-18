package service

import (
	"context"
	"fmt"
	"time"

	apperror "github.com/garyjdn/go-apperror"
	"github.com/golang-jwt/jwt/v5"
	"github.com/patrickmn/go-cache"
	"gitlab.jatimprov.go.id/pharosia/auth-utils/types"
	authv1 "gitlab.jatimprov.go.id/pharosia/proto-auth/v1"
	"google.golang.org/grpc"
)

type JWTValidator interface {
	ValidateTokenLocally(tokenString string) (*types.UserContext, error)
	ValidateTokenLocallyWithContext(ctx context.Context, tokenString string) (*types.UserContext, error)
	ValidateTokenWithFallback(ctx context.Context, tokenString string) (*types.UserContext, error)
	ParseTokenClaims(tokenString string) (jwt.MapClaims, error)
	IsTokenRevoked(tokenString string) bool
	RevokeToken(tokenString string)
}

type jwtValidator struct {
	config      *types.JWTConfig
	tokenCache  *cache.Cache
	authClient  authv1.AuthServiceClient
	auditLogger types.AuditLogger
}

func NewJWTValidator(config *types.JWTConfig, auditLogger types.AuditLogger) JWTValidator {
	v := &jwtValidator{
		config:      config,
		tokenCache:  nil,
		auditLogger: auditLogger,
	}

	if config.EnableCache {
		v.tokenCache = cache.New(config.CacheTTL, 2*config.CacheTTL)
	}

	if config.EnableFallback && config.AuthServiceURL != "" {
		conn, err := grpc.Dial(config.AuthServiceURL, grpc.WithInsecure())
		if err == nil {
			v.authClient = authv1.NewAuthServiceClient(conn)
		}
	}

	return v
}

func (v *jwtValidator) ValidateTokenLocally(tokenString string) (*types.UserContext, error) {
	return v.ValidateTokenLocallyWithContext(context.Background(), tokenString)
}

func (v *jwtValidator) ValidateTokenLocallyWithContext(ctx context.Context, tokenString string) (*types.UserContext, error) {
	// Parse token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			// Log suspicious activity
			v.logSecurityEvent(ctx, types.AuditEventSuspiciousActivity, map[string]interface{}{
				"reason": "invalid_signing_method",
				"method": token.Header["alg"],
			})
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(v.config.Secret), nil
	})

	if err != nil {
		v.logAuthEvent(ctx, types.AuditEventTokenValidated, "", err.Error(), false, map[string]interface{}{
			"token_preview": v.getTokenPreview(tokenString),
		})
		return nil, apperror.NewAppError(401, "Invalid token format", err)
	}

	if !token.Valid {
		v.logAuthEvent(ctx, types.AuditEventTokenValidated, "", "token_invalid", false, nil)
		return nil, apperror.ErrUnauthorized
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		v.logAuthEvent(ctx, types.AuditEventTokenValidated, "", "invalid_claims", false, nil)
		return nil, apperror.NewAppError(401, "Invalid token claims", nil)
	}

	// Check expiry
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			userID, _ := claims["user_id"].(string)
			v.logAuthEvent(ctx, types.AuditEventTokenExpired, userID, "token_expired", false, map[string]interface{}{
				"expired_at": time.Unix(int64(exp), 0),
			})
			return nil, apperror.NewAppError(401, "Token expired", nil)
		}
	}

	// Check issuer
	if iss, ok := claims["iss"].(string); ok && v.config.Issuer != "" {
		if iss != v.config.Issuer {
			v.logSecurityEvent(ctx, types.AuditEventSuspiciousActivity, map[string]interface{}{
				"reason":        "invalid_issuer",
				"issuer":        iss,
				"expected":      v.config.Issuer,
				"token_preview": v.getTokenPreview(tokenString),
			})
			return nil, apperror.NewAppError(401, "Invalid token issuer", nil)
		}
	}

	// Check if token is revoked
	if v.IsTokenRevoked(tokenString) {
		userID, _ := claims["user_id"].(string)
		v.logAuthEvent(ctx, types.AuditEventTokenRevoked, userID, "token_revoked", false, nil)
		return nil, apperror.NewAppError(401, "Token revoked", nil)
	}

	// Build user context
	userID, _ := claims["user_id"].(string)
	username, _ := claims["username"].(string)
	email, _ := claims["email"].(string)

	var expiry time.Time
	if exp, ok := claims["exp"].(float64); ok {
		expiry = time.Unix(int64(exp), 0)
	}

	// Log successful validation
	v.logAuthEvent(ctx, types.AuditEventTokenValidated, userID, "validation_success", true, map[string]interface{}{
		"username":   username,
		"expires_at": expiry,
	})

	return &types.UserContext{
		UserID:      userID,
		Username:    username,
		Email:       email,
		Roles:       make(map[string]string), // Akan di-load oleh service-specific adapter
		Permissions: []string{},              // Akan dihitung oleh RBAC middleware
		TokenExpiry: expiry,
		Claims:      claims,
	}, nil
}

func (v *jwtValidator) ValidateTokenWithFallback(ctx context.Context, tokenString string) (*types.UserContext, error) {
	// Coba local validation dulu
	userCtx, err := v.ValidateTokenLocallyWithContext(ctx, tokenString)
	if err == nil {
		return userCtx, nil
	}

	// Jika local validation gagal dan fallback enabled
	if v.config.EnableFallback && v.authClient != nil {
		resp, err := v.authClient.ValidateToken(ctx, &authv1.ValidateTokenRequest{
			AccessToken: tokenString,
		})

		if err == nil && resp.IsValid {
			// Cache valid token untuk future requests
			if v.tokenCache != nil {
				v.tokenCache.Set(tokenString, resp.UserId, v.config.CacheTTL)
			}

			// Log fallback validation success
			v.logAuthEvent(ctx, types.AuditEventTokenValidated, resp.UserId, "fallback_validation_success", true, map[string]interface{}{
				"source": "auth_service",
			})

			return &types.UserContext{
				UserID: resp.UserId,
				Roles:  make(map[string]string),
			}, nil
		} else {
			// Log fallback validation failure
			v.logAuthEvent(ctx, types.AuditEventTokenValidated, "", "fallback_validation_failed", false, map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	return nil, apperror.ErrUnauthorized
}

func (v *jwtValidator) ParseTokenClaims(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(v.config.Secret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (v *jwtValidator) IsTokenRevoked(tokenString string) bool {
	if v.tokenCache == nil {
		return false
	}

	if revoked, found := v.tokenCache.Get("revoked:" + tokenString); found {
		return revoked.(bool)
	}

	return false
}

func (v *jwtValidator) RevokeToken(tokenString string) {
	if v.tokenCache != nil {
		v.tokenCache.Set("revoked:"+tokenString, true, v.config.CacheTTL)
	}

	// Log token revocation
	v.logAuthEvent(context.Background(), types.AuditEventTokenRevoked, "", "token_revoked", true, map[string]interface{}{
		"token_preview": v.getTokenPreview(tokenString),
	})
}

// Helper methods for audit logging
func (v *jwtValidator) logAuthEvent(ctx context.Context, eventType types.AuditEventType, userID, reason string, success bool, metadata map[string]interface{}) {
	if v.auditLogger != nil {
		v.auditLogger.LogAuthEvent(ctx, eventType, userID, reason, success, metadata)
	}
}

func (v *jwtValidator) logSecurityEvent(ctx context.Context, eventType types.AuditEventType, details map[string]interface{}) {
	if v.auditLogger != nil {
		v.auditLogger.LogSecurityEvent(ctx, eventType, details)
	}
}

func (v *jwtValidator) getTokenPreview(token string) string {
	if len(token) > 20 {
		return token[:10] + "..." + token[len(token)-10:]
	}
	return token
}
