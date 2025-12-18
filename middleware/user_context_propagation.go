package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/garyjdn/go-authutils/service"
	"github.com/garyjdn/go-authutils/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// UserContextPropagation handles propagation of user context between services
type UserContextPropagation struct {
	auditLogger types.AuditLogger
}

// NewUserContextPropagation creates a new user context propagation handler
func NewUserContextPropagation(auditLogger types.AuditLogger) *UserContextPropagation {
	return &UserContextPropagation{
		auditLogger: auditLogger,
	}
}

// PropagateUserContextToGRPC propagates user context to gRPC calls
func (ucp *UserContextPropagation) PropagateUserContextToGRPC(ctx context.Context, userContext *types.UserContext) context.Context {
	if userContext == nil {
		return ctx
	}

	// Serialize user context
	userContextJSON, err := json.Marshal(userContext)
	if err != nil {
		ucp.logAuditEvent(ctx, types.AuditEventAccessDenied, userContext.UserID, "user_context_serialization_failed", false, err.Error())
		return ctx
	}

	// Add user context to metadata
	md := metadata.New(map[string]string{
		"x-user-context": string(userContextJSON),
		"x-user-id":      userContext.UserID,
		"x-request-id":   ucp.extractRequestID(ctx),
	})

	return metadata.NewOutgoingContext(ctx, md)
}

// ExtractUserContextFromGRPC extracts user context from gRPC metadata
func (ucp *UserContextPropagation) ExtractUserContextFromGRPC(ctx context.Context) (*types.UserContext, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("no metadata found in context")
	}

	// Try to extract from x-user-context header first
	userContextHeaders := md["x-user-context"]
	if len(userContextHeaders) > 0 {
		var userContext types.UserContext
		if err := json.Unmarshal([]byte(userContextHeaders[0]), &userContext); err == nil {
			ucp.logAuditEvent(ctx, types.AuditEventAccessGranted, userContext.UserID, "user_context_extracted", true, "user_context_propagated")
			return &userContext, nil
		}
	}

	// Fallback to individual headers
	userIDHeaders := md["x-user-id"]
	if len(userIDHeaders) == 0 {
		return nil, fmt.Errorf("no user context found in metadata")
	}

	// Build minimal user context from headers
	userContext := &types.UserContext{
		UserID: userIDHeaders[0],
	}

	// Extract additional fields if available
	if emailHeaders := md["x-user-email"]; len(emailHeaders) > 0 {
		userContext.Email = emailHeaders[0]
	}

	if usernameHeaders := md["x-user-username"]; len(usernameHeaders) > 0 {
		userContext.Username = usernameHeaders[0]
	}

	// Note: SessionID is not in the original UserContext struct, skipping for now
	// if sessionHeaders := md["x-session-id"]; len(sessionHeaders) > 0 {
	//     userContext.SessionID = sessionHeaders[0]
	// }

	ucp.logAuditEvent(ctx, types.AuditEventAccessGranted, userContext.UserID, "user_context_extracted", true, "user_context_from_headers")
	return userContext, nil
}

// HTTPMiddleware extracts user context from HTTP headers and adds to context
func (ucp *UserContextPropagation) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract user context from headers
		userContext, err := ucp.extractUserContextFromHTTP(r)
		if err != nil {
			// For user context propagation, we don't fail the request if user context is missing
			// This allows the endpoint to work for both user requests and service-to-service calls
			next.ServeHTTP(w, r)
			return
		}

		// Add user context to request context
		ctx := context.WithValue(r.Context(), types.UserPropagationKey, userContext)

		ucp.logAuditEvent(ctx, types.AuditEventAccessGranted, userContext.UserID, "user_context_propagated", true, "http_user_context")

		// Call next handler with updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GRPCUnaryInterceptor extracts user context from gRPC metadata
func (ucp *UserContextPropagation) GRPCUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Extract user context from metadata
		userContext, err := ucp.ExtractUserContextFromGRPC(ctx)
		if err != nil {
			// Continue without user context for service-to-service calls
			return handler(ctx, req)
		}

		// Add user context to request context
		ctx = context.WithValue(ctx, types.UserPropagationKey, userContext)

		// Call the handler with updated context
		return handler(ctx, req)
	}
}

// GRPCStreamInterceptor extracts user context from gRPC stream metadata
func (ucp *UserContextPropagation) GRPCStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Extract user context from metadata
		userContext, err := ucp.ExtractUserContextFromGRPC(ss.Context())
		if err != nil {
			// Continue without user context for service-to-service calls
			return handler(srv, ss)
		}

		// Add user context to stream context
		ctx := context.WithValue(ss.Context(), types.UserPropagationKey, userContext)

		// Create wrapped stream with updated context
		wrappedStream := &contextAwareStream{
			ServerStream: ss,
			ctx:          ctx,
		}

		// Call the handler with wrapped stream
		return handler(srv, wrappedStream)
	}
}

// extractUserContextFromHTTP extracts user context from HTTP headers
func (ucp *UserContextPropagation) extractUserContextFromHTTP(r *http.Request) (*types.UserContext, error) {
	// Try to extract from x-user-context header first
	userContextHeader := r.Header.Get("X-User-Context")
	if userContextHeader != "" {
		var userContext types.UserContext
		if err := json.Unmarshal([]byte(userContextHeader), &userContext); err == nil {
			return &userContext, nil
		}
	}

	// Fallback to individual headers
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		return nil, fmt.Errorf("no user context found in headers")
	}

	// Build minimal user context from headers
	userContext := &types.UserContext{
		UserID: userID,
	}

	// Extract additional fields if available
	if email := r.Header.Get("X-User-Email"); email != "" {
		userContext.Email = email
	}

	if username := r.Header.Get("X-User-Username"); username != "" {
		userContext.Username = username
	}

	// Note: SessionID is not in the original UserContext struct, skipping for now
	// if sessionID := r.Header.Get("X-Session-ID"); sessionID != "" {
	//     userContext.SessionID = sessionID
	// }

	return userContext, nil
}

// extractRequestID extracts request ID from context or generates a new one
func (ucp *UserContextPropagation) extractRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(types.RequestIDKey).(string); ok {
		return requestID
	}
	return service.GenerateRequestID()
}

// logAuditEvent logs audit events
func (ucp *UserContextPropagation) logAuditEvent(ctx context.Context, eventType types.AuditEventType, userID, reason string, success bool, details string) {
	if ucp.auditLogger != nil {
		ucp.auditLogger.LogAuthEvent(ctx, eventType, userID, reason, success, map[string]interface{}{
			"component": "user_context_propagation",
			"details":   details,
		})
	}
}

// Helper functions for user context propagation

// GetUserContextFromContext extracts propagated user context from context
func GetUserContextFromContext(ctx context.Context) (*types.UserContext, bool) {
	userContext, ok := ctx.Value(types.UserPropagationKey).(*types.UserContext)
	return userContext, ok
}

// HasUserContext checks if user context is present in the request
func HasUserContext(ctx context.Context) bool {
	_, ok := GetUserContextFromContext(ctx)
	return ok
}

// WithUserContext adds user context to context for outgoing calls
func WithUserContext(ctx context.Context, userContext *types.UserContext) context.Context {
	if userContext == nil {
		return ctx
	}
	return context.WithValue(ctx, types.UserPropagationKey, userContext)
}

// ClientInterceptor creates a gRPC client interceptor for propagating user context
func (ucp *UserContextPropagation) ClientInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		// Check if user context is present
		if userContext, ok := GetUserContextFromContext(ctx); ok {
			// Propagate user context to outgoing call
			ctx = ucp.PropagateUserContextToGRPC(ctx, userContext)
		}

		// Make the call with updated context
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// HTTPClientInterceptor adds user context headers to HTTP requests
func (ucp *UserContextPropagation) HTTPClientInterceptor(req *http.Request) *http.Request {
	// Check if user context is present in request context
	if userContext, ok := GetUserContextFromContext(req.Context()); ok {
		// Serialize user context
		userContextJSON, err := json.Marshal(userContext)
		if err == nil {
			// Add user context header
			req.Header.Set("X-User-Context", string(userContextJSON))
		} else {
			// Fallback to individual headers
			req.Header.Set("X-User-ID", userContext.UserID)
			if userContext.Email != "" {
				req.Header.Set("X-User-Email", userContext.Email)
			}
			if userContext.Username != "" {
				req.Header.Set("X-User-Username", userContext.Username)
			}
			// Note: SessionID is not in the original UserContext struct, skipping for now
			// if userContext.SessionID != "" {
			//     req.Header.Set("X-Session-ID", userContext.SessionID)
			// }
		}
	}

	return req
}
