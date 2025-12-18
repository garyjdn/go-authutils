package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"gitlab.jatimprov.go.id/pharosia/auth-utils/service"
	"gitlab.jatimprov.go.id/pharosia/auth-utils/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ServiceAuthMiddleware provides authentication for service-to-service communication
type ServiceAuthMiddleware struct {
	serviceManager *service.ServiceAccountManager
	auditLogger    types.AuditLogger
}

// NewServiceAuthMiddleware creates a new service auth middleware
func NewServiceAuthMiddleware(serviceManager *service.ServiceAccountManager, auditLogger types.AuditLogger) *ServiceAuthMiddleware {
	return &ServiceAuthMiddleware{
		serviceManager: serviceManager,
		auditLogger:    auditLogger,
	}
}

// HTTPMiddleware returns an HTTP middleware for service authentication
func (sam *ServiceAuthMiddleware) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract service token from header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			sam.logAuditEvent(r.Context(), types.AuditEventAccessDenied, "", "missing_service_token", false, "missing Authorization header")
			http.Error(w, "Missing service token", http.StatusUnauthorized)
			return
		}

		// Parse Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			sam.logAuditEvent(r.Context(), types.AuditEventAccessDenied, "", "invalid_token_format", false, "invalid Authorization header format")
			http.Error(w, "Invalid token format", http.StatusUnauthorized)
			return
		}

		token := parts[1]

		// Validate service token
		serviceAccount, err := sam.serviceManager.ValidateServiceToken(token)
		if err != nil {
			sam.logAuditEvent(r.Context(), types.AuditEventAccessDenied, "", "service_token_validation_failed", false, err.Error())
			http.Error(w, "Invalid service token", http.StatusUnauthorized)
			return
		}

		// Add service context to request
		ctx := context.WithValue(r.Context(), types.ServiceContextKey, serviceAccount)
		ctx = context.WithValue(ctx, types.ServiceTokenKey, token)

		sam.logAuditEvent(ctx, types.AuditEventAccessGranted, serviceAccount.ServiceID, "service_authentication", true, "service_token_valid")

		// Call next handler with updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GRPCUnaryInterceptor returns a gRPC unary interceptor for service authentication
func (sam *ServiceAuthMiddleware) GRPCUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Extract service token from metadata
		token, err := sam.extractGRPCServiceToken(ctx)
		if err != nil {
			sam.logAuditEvent(ctx, types.AuditEventAccessDenied, "", "missing_service_token", false, err.Error())
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}

		// Validate service token
		serviceAccount, err := sam.serviceManager.ValidateServiceToken(token)
		if err != nil {
			sam.logAuditEvent(ctx, types.AuditEventAccessDenied, "", "service_token_validation_failed", false, err.Error())
			return nil, status.Error(codes.Unauthenticated, "Invalid service token")
		}

		// Add service context to request
		ctx = context.WithValue(ctx, types.ServiceContextKey, serviceAccount)
		ctx = context.WithValue(ctx, types.ServiceTokenKey, token)

		sam.logAuditEvent(ctx, types.AuditEventAccessGranted, serviceAccount.ServiceID, "service_authentication", true, "service_token_valid")

		// Call the handler with updated context
		return handler(ctx, req)
	}
}

// GRPCStreamInterceptor returns a gRPC stream interceptor for service authentication
func (sam *ServiceAuthMiddleware) GRPCStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Extract service token from metadata
		token, err := sam.extractGRPCServiceToken(ss.Context())
		if err != nil {
			sam.logAuditEvent(ss.Context(), types.AuditEventAccessDenied, "", "missing_service_token", false, err.Error())
			return status.Error(codes.Unauthenticated, err.Error())
		}

		// Validate service token
		serviceAccount, err := sam.serviceManager.ValidateServiceToken(token)
		if err != nil {
			sam.logAuditEvent(ss.Context(), types.AuditEventAccessDenied, "", "service_token_validation_failed", false, err.Error())
			return status.Error(codes.Unauthenticated, "Invalid service token")
		}

		// Add service context to stream
		ctx := context.WithValue(ss.Context(), types.ServiceContextKey, serviceAccount)
		ctx = context.WithValue(ctx, types.ServiceTokenKey, token)

		// Create wrapped stream with updated context
		wrappedStream := &contextAwareStream{
			ServerStream: ss,
			ctx:          ctx,
		}

		sam.logAuditEvent(ctx, types.AuditEventAccessGranted, serviceAccount.ServiceID, "service_authentication", true, "service_token_valid")

		// Call the handler with wrapped stream
		return handler(srv, wrappedStream)
	}
}

// extractGRPCServiceToken extracts service token from gRPC metadata
func (sam *ServiceAuthMiddleware) extractGRPCServiceToken(ctx context.Context) (string, error) {
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

// logAuditEvent logs audit events
func (sam *ServiceAuthMiddleware) logAuditEvent(ctx context.Context, eventType types.AuditEventType, serviceID, reason string, success bool, details string) {
	if sam.auditLogger != nil {
		sam.auditLogger.LogAuthEvent(ctx, eventType, serviceID, reason, success, map[string]interface{}{
			"service_id": serviceID,
			"details":    details,
			"component":  "service_auth_middleware",
		})
	}
}

// contextAwareStream wraps grpc.ServerStream to provide updated context
type contextAwareStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *contextAwareStream) Context() context.Context {
	return s.ctx
}

// Helper functions for extracting service context from requests

// GetServiceAccountFromContext extracts service account from context
func GetServiceAccountFromContext(ctx context.Context) (*types.ServiceAccount, bool) {
	serviceAccount, ok := ctx.Value(types.ServiceContextKey).(*types.ServiceAccount)
	return serviceAccount, ok
}

// GetServiceTokenFromContext extracts service token from context
func GetServiceTokenFromContext(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(types.ServiceTokenKey).(string)
	return token, ok
}

// RequireServicePermission checks if service has required permission
func RequireServicePermission(ctx context.Context, requiredPermission string) error {
	serviceAccount, ok := GetServiceAccountFromContext(ctx)
	if !ok {
		return fmt.Errorf("service account not found in context")
	}

	if !serviceAccount.HasPermission(requiredPermission) {
		return fmt.Errorf("service account %s does not have permission %s", serviceAccount.ServiceID, requiredPermission)
	}

	return nil
}
