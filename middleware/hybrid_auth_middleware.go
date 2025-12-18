package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/garyjdn/go-authutils/service"
	"github.com/garyjdn/go-authutils/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// AuthType represents the type of authentication used
type AuthType int

const (
	AuthTypeNone AuthType = iota
	AuthTypeUser
	AuthTypeService
)

// AuthContext contains authentication context information
type AuthContext struct {
	Type        AuthType
	UserContext *types.UserContext
	ServiceAcct *types.ServiceAccount
	Token       string
	RequestID   string
}

// HybridAuthMiddleware provides hybrid authentication for both users and services
type HybridAuthMiddleware struct {
	jwtValidator     service.JWTValidator
	serviceManager   *service.ServiceAccountManager
	userPropagation  *UserContextPropagation
	auditLogger      types.AuditLogger
	allowServiceOnly bool
}

// NewHybridAuthMiddleware creates a new hybrid auth middleware
func NewHybridAuthMiddleware(
	jwtValidator service.JWTValidator,
	serviceManager *service.ServiceAccountManager,
	userPropagation *UserContextPropagation,
	auditLogger types.AuditLogger,
	options ...HybridAuthOption,
) *HybridAuthMiddleware {
	config := &HybridAuthConfig{
		AllowServiceOnly: false,
	}

	for _, option := range options {
		option(config)
	}

	return &HybridAuthMiddleware{
		jwtValidator:     jwtValidator,
		serviceManager:   serviceManager,
		userPropagation:  userPropagation,
		auditLogger:      auditLogger,
		allowServiceOnly: config.AllowServiceOnly,
	}
}

// HybridAuthOption configures the hybrid auth middleware
type HybridAuthOption func(*HybridAuthConfig)

type HybridAuthConfig struct {
	AllowServiceOnly bool
}

// WithServiceOnlyAllowed allows service-only authentication
func WithServiceOnlyAllowed(allowed bool) HybridAuthOption {
	return func(config *HybridAuthConfig) {
		config.AllowServiceOnly = allowed
	}
}

// HTTPMiddleware returns an HTTP middleware for hybrid authentication
func (ham *HybridAuthMiddleware) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authCtx, err := ham.authenticateHTTPRequest(r)
		if err != nil {
			ham.logAuthEvent(r.Context(), types.AuditEventAccessDenied, "", "http_authentication_failed", false, err.Error())
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Add auth context to request
		ctx := context.WithValue(r.Context(), types.UserContextKey, authCtx)

		ham.logAuthEvent(ctx, types.AuditEventAccessGranted, ham.getSubjectFromAuthContext(authCtx), "http_authentication", true, "authentication_successful")

		// Call next handler with updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GRPCUnaryInterceptor returns a gRPC unary interceptor for hybrid authentication
func (ham *HybridAuthMiddleware) GRPCUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		authCtx, err := ham.authenticateGRPCRequest(ctx)
		if err != nil {
			ham.logAuthEvent(ctx, types.AuditEventAccessDenied, "", "grpc_authentication_failed", false, err.Error())
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}

		// Add auth context to request
		ctx = context.WithValue(ctx, types.UserContextKey, authCtx)

		ham.logAuthEvent(ctx, types.AuditEventAccessGranted, ham.getSubjectFromAuthContext(authCtx), "grpc_authentication", true, "authentication_successful")

		// Call the handler with updated context
		return handler(ctx, req)
	}
}

// GRPCStreamInterceptor returns a gRPC stream interceptor for hybrid authentication
func (ham *HybridAuthMiddleware) GRPCStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		authCtx, err := ham.authenticateGRPCRequest(ss.Context())
		if err != nil {
			ham.logAuthEvent(ss.Context(), types.AuditEventAccessDenied, "", "grpc_authentication_failed", false, err.Error())
			return status.Error(codes.Unauthenticated, err.Error())
		}

		// Add auth context to stream
		ctx := context.WithValue(ss.Context(), types.UserContextKey, authCtx)

		// Create wrapped stream with updated context
		wrappedStream := &contextAwareStream{
			ServerStream: ss,
			ctx:          ctx,
		}

		ham.logAuthEvent(ctx, types.AuditEventAccessGranted, ham.getSubjectFromAuthContext(authCtx), "grpc_authentication", true, "authentication_successful")

		// Call the handler with wrapped stream
		return handler(srv, wrappedStream)
	}
}

// authenticateHTTPRequest authenticates an HTTP request
func (ham *HybridAuthMiddleware) authenticateHTTPRequest(r *http.Request) (*AuthContext, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing authorization header")
	}

	// Parse Bearer token
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return nil, fmt.Errorf("invalid authorization header format")
	}

	token := parts[1]

	// Try user authentication first
	if userContext, err := ham.jwtValidator.ValidateTokenLocallyWithContext(r.Context(), token); err == nil {
		// Extract propagated user context if available
		if propagatedUserCtx, err := ham.userPropagation.ExtractUserContextFromGRPC(r.Context()); err == nil {
			// Merge user contexts
			userContext.UserID = propagatedUserCtx.UserID
			if propagatedUserCtx.Email != "" {
				userContext.Email = propagatedUserCtx.Email
			}
			if propagatedUserCtx.Username != "" {
				userContext.Username = propagatedUserCtx.Username
			}
		}

		return &AuthContext{
			Type:        AuthTypeUser,
			UserContext: userContext,
			Token:       token,
			RequestID:   ham.extractRequestID(r.Context()),
		}, nil
	}

	// Try service authentication
	if serviceAccount, err := ham.serviceManager.ValidateServiceToken(token); err == nil {
		return &AuthContext{
			Type:        AuthTypeService,
			ServiceAcct: serviceAccount,
			Token:       token,
			RequestID:   ham.extractRequestID(r.Context()),
		}, nil
	}

	return nil, fmt.Errorf("invalid authentication token")
}

// authenticateGRPCRequest authenticates a gRPC request
func (ham *HybridAuthMiddleware) authenticateGRPCRequest(ctx context.Context) (*AuthContext, error) {
	// Extract token from metadata
	token, err := ham.extractTokenFromGRPC(ctx)
	if err != nil {
		return nil, err
	}

	// Try user authentication first
	if userContext, err := ham.jwtValidator.ValidateTokenLocallyWithContext(ctx, token); err == nil {
		// Extract propagated user context if available
		if propagatedUserCtx, err := ham.userPropagation.ExtractUserContextFromGRPC(ctx); err == nil {
			// Merge user contexts
			userContext.UserID = propagatedUserCtx.UserID
			if propagatedUserCtx.Email != "" {
				userContext.Email = propagatedUserCtx.Email
			}
			if propagatedUserCtx.Username != "" {
				userContext.Username = propagatedUserCtx.Username
			}
		}

		return &AuthContext{
			Type:        AuthTypeUser,
			UserContext: userContext,
			Token:       token,
			RequestID:   ham.extractRequestID(ctx),
		}, nil
	}

	// Try service authentication
	if serviceAccount, err := ham.serviceManager.ValidateServiceToken(token); err == nil {
		return &AuthContext{
			Type:        AuthTypeService,
			ServiceAcct: serviceAccount,
			Token:       token,
			RequestID:   ham.extractRequestID(ctx),
		}, nil
	}

	return nil, fmt.Errorf("invalid authentication token")
}

// extractTokenFromGRPC extracts token from gRPC metadata
func (ham *HybridAuthMiddleware) extractTokenFromGRPC(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", fmt.Errorf("missing metadata")
	}

	// Check authorization header
	authHeaders := md["authorization"]
	if len(authHeaders) == 0 {
		return "", fmt.Errorf("missing authorization header")
	}

	for _, authHeader := range authHeaders {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && parts[0] == "Bearer" {
			return parts[1], nil
		}
	}

	return "", fmt.Errorf("invalid authorization header format")
}

// extractRequestID extracts request ID from context
func (ham *HybridAuthMiddleware) extractRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(types.RequestIDKey).(string); ok {
		return requestID
	}
	return service.GenerateRequestID()
}

// getSubjectFromAuthContext extracts subject identifier from auth context
func (ham *HybridAuthMiddleware) getSubjectFromAuthContext(authCtx *AuthContext) string {
	switch authCtx.Type {
	case AuthTypeUser:
		return authCtx.UserContext.UserID
	case AuthTypeService:
		return authCtx.ServiceAcct.ServiceID
	default:
		return "unknown"
	}
}

// logAuthEvent logs audit events
func (ham *HybridAuthMiddleware) logAuthEvent(ctx context.Context, eventType types.AuditEventType, subject, reason string, success bool, details string) {
	if ham.auditLogger != nil {
		ham.auditLogger.LogAuthEvent(ctx, eventType, subject, reason, success, map[string]interface{}{
			"component": "hybrid_auth_middleware",
			"details":   details,
		})
	}
}

// Helper functions for extracting auth context from requests

// GetAuthContextFromContext extracts auth context from context
func GetAuthContextFromContext(ctx context.Context) (*AuthContext, bool) {
	authCtx, ok := ctx.Value(types.UserContextKey).(*AuthContext)
	return authCtx, ok
}

// IsUserAuthenticated checks if user is authenticated
func IsUserAuthenticated(ctx context.Context) bool {
	authCtx, ok := GetAuthContextFromContext(ctx)
	return ok && authCtx.Type == AuthTypeUser
}

// IsServiceAuthenticated checks if service is authenticated
func IsServiceAuthenticated(ctx context.Context) bool {
	authCtx, ok := GetAuthContextFromContext(ctx)
	return ok && authCtx.Type == AuthTypeService
}

// GetUserContextFromAuthContext extracts user context from auth context
func GetUserContextFromAuthContext(ctx context.Context) (*types.UserContext, bool) {
	authCtx, ok := GetAuthContextFromContext(ctx)
	if !ok || authCtx.Type != AuthTypeUser {
		return nil, false
	}
	return authCtx.UserContext, true
}

// GetServiceAccountFromAuthContext extracts service account from auth context
func GetServiceAccountFromAuthContext(ctx context.Context) (*types.ServiceAccount, bool) {
	authCtx, ok := GetAuthContextFromContext(ctx)
	if !ok || authCtx.Type != AuthTypeService {
		return nil, false
	}
	return authCtx.ServiceAcct, true
}

// RequireUserAuthentication ensures that user is authenticated
func RequireUserAuthentication(ctx context.Context) error {
	if !IsUserAuthenticated(ctx) {
		return fmt.Errorf("user authentication required")
	}
	return nil
}

// RequireServiceAuthentication ensures that service is authenticated
func RequireServiceAuthentication(ctx context.Context) error {
	if !IsServiceAuthenticated(ctx) {
		return fmt.Errorf("service authentication required")
	}
	return nil
}

// RequireAnyAuthentication ensures that either user or service is authenticated
func RequireAnyAuthentication(ctx context.Context) error {
	if !IsUserAuthenticated(ctx) && !IsServiceAuthenticated(ctx) {
		return fmt.Errorf("authentication required")
	}
	return nil
}
