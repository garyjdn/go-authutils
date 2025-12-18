# Auth Utils - Comprehensive Authentication & Authorization Library

## Overview

Auth Utils adalah library Go yang menyediakan solusi lengkap untuk authentication dan authorization dalam microservices architecture. Library ini dirancang untuk mendukung berbagai pattern keamanan mulai dari user JWT authentication hingga service-to-service communication dengan RBAC (Role-Based Access Control).

## Features

### 🔐 Authentication
- **JWT Token Validation**: Local validation dengan fallback ke auth service
- **Service Account Authentication**: Untuk komunikasi antar service
- **Hybrid Authentication**: Mendukung both user JWT dan service tokens
- **Token Caching**: Performance optimization dengan token cache
- **Token Revocation**: Support untuk token revocation

### 🛡️ Authorization
- **Role-Based Access Control (RBAC)**: Hierarchical role system
- **Permission Matrix**: Flexible permission configuration
- **Resource-based Authorization**: Fine-grained access control
- **Dynamic Permission Loading**: Runtime permission calculation

### 📊 Audit & Logging
- **Multi-channel Logging**: Console, file, dan Kafka
- **Structured Audit Events**: Comprehensive security event tracking
- **Performance Metrics**: Request timing dan cache statistics
- **Security Event Monitoring**: Suspicious activity detection

### 🚀 Performance Optimization
- **Permission Caching**: Redis-like caching untuk permissions
- **Token Validation Caching**: Reduce auth service calls
- **Connection Pooling**: Optimized database connections
- **Lazy Loading**: On-demand permission calculation

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client       │    │  API Gateway    │    │  Site Service   │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          │ JWT Token            │ Service Token         │ User Context
          ▼                      ▼                      ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Auth Service   │    │ Service Auth    │    │ RBAC Middleware │
│ (JWT Issuer)  │    │ (Service Acct)  │    │ (Permissions)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Quick Start

### 1. Basic Setup

```go
import (
    "gitlab.jatimprov.go.id/pharosia/auth-utils"
    "gitlab.jatimprov.go.id/pharosia/auth-utils/config"
    "gitlab.jatimprov.go.id/pharosia/auth-utils/middleware"
    "gitlab.jatimprov.go.id/pharosia/auth-utils/types"
)

// Initialize JWT configuration
jwtConfig := &types.JWTConfig{
    Secret:         os.Getenv("JWT_SECRET"),
    Issuer:         "pharosia-auth",
    TokenExpiry:    15 * time.Minute,
    EnableCache:    true,
    CacheTTL:       5 * time.Minute,
    EnableFallback: true,
    AuthServiceURL: "auth-service:9090",
}

// Initialize audit logging
auditConfig := config.LoadAuditConfig()
auditLogger := config.NewAuditLogger("my-service", auditConfig)

// Initialize JWT validator
jwtValidator := authutils.NewJWTValidator(jwtConfig, auditLogger)
```

### 2. User Authentication

```go
// HTTP Middleware
jwtMiddleware := authutils.NewJWTMiddleware(jwtValidator)
router.Use(jwtMiddleware.RequireAuthentication)

// gRPC Interceptor
grpcServer := grpc.NewServer(
    grpc.UnaryInterceptor(jwtMiddleware.GRPCUnaryInterceptor()),
)
```

### 3. Service Account Authentication

```go
// Initialize service account manager
serviceManager := authutils.NewServiceAccountManager(
    jwtSecret,
    jwtIssuer,
    authutils.WithCacheExpiry(1*time.Hour),
    authutils.WithCacheEnabled(true),
)

// Register service account
serviceAccount, err := serviceManager.RegisterServiceAccount(
    "my-service",
    "My Service",
    []string{"resource:read", "resource:write"},
    map[string]string{"version": "1.0.0"},
)

// Generate service token
serviceToken, err := serviceManager.GenerateServiceToken(
    "my-service",
    1*time.Hour,
)
```

### 4. Hybrid Authentication (User + Service)

```go
// Initialize hybrid auth middleware
hybridAuth := authutils.NewHybridAuthMiddleware(
    jwtValidator,
    serviceManager,
    userPropagation,
    auditLogger,
    authutils.WithServiceOnlyAllowed(true),
)

// Apply to HTTP router
router.Use(hybridAuth.HTTPMiddleware)

// Apply to gRPC server
grpcServer := grpc.NewServer(
    grpc.UnaryInterceptor(hybridAuth.GRPCUnaryInterceptor()),
    grpc.StreamInterceptor(hybridAuth.GRPCStreamInterceptor()),
)
```

### 5. Role-Based Access Control

```go
// Define permission matrix
permissionMatrix := permissions.SitePermissionMatrix

// Initialize RBAC middleware
rbac := authutils.NewRBACMiddleware(
    "site-service",
    permissionMatrix,
    nil, // custom permission loader
    auditLogger,
)

// Apply to routes
router.With(rbac.RequirePermission("site", "read")).Get("/", handler)
router.With(rbac.RequirePermission("site", "write")).Post("/", handler)
```

### 6. Permission Caching

```go
// Initialize permission cache
permissionCache := cache.NewCacheManager(
    true, // enabled
    30*time.Minute, // default TTL
    10*time.Minute, // cleanup TTL
)

// Cache user permissions
err := permissionCache.CacheUserPermissions(
    ctx,
    userID,
    []string{"site:read", "page:write"},
    15*time.Minute,
)

// Get cached permissions
permissions, found := permissionCache.GetUserPermissions(ctx, userID)
```

## Configuration

### Environment Variables

```bash
# JWT Configuration
JWT_SECRET=your-secret-key
JWT_ISSUER=pharosia-auth
AUTH_SERVICE_URL=auth-service:9090

# Audit Configuration
AUDIT_CONSOLE=true
AUDIT_FILE=false
AUDIT_FILE_PATH=/var/log/audit.log
AUDIT_KAFKA=true
AUDIT_KAFKA_TOPIC=audit.events
AUDIT_KAFKA_BROKERS=kafka:9092

# Cache Configuration
CACHE_ENABLED=true
CACHE_TTL=5m
CACHE_CLEANUP_INTERVAL=10m
```

### Permission Matrix

```go
// Define site permissions
SitePermissionMatrix = permissions.RolePermissionMatrix{
    "owner": {
        "site":   {"read", "write", "delete", "manage"},
        "page":   {"read", "write", "delete", "create"},
        "member": {"read", "write", "delete", "invite"},
    },
    "admin": {
        "site":   {"read", "write", "invite"},
        "page":   {"read", "write", "delete", "create"},
        "member": {"read", "write", "invite"},
    },
    "member": {
        "site":   {"read"},
        "page":   {"read", "write", "create"},
        "member": {"read"},
    },
}
```

## Security Best Practices

### 1. Token Management
- Use short-lived tokens (15 minutes for user tokens)
- Implement token refresh mechanism
- Store service tokens securely
- Rotate service keys regularly

### 2. Permission Design
- Follow principle of least privilege
- Use hierarchical roles
- Implement resource-based permissions
- Regular permission audits

### 3. Audit & Monitoring
- Log all authentication events
- Monitor failed login attempts
- Track permission changes
- Set up alerts for suspicious activity

### 4. Performance Optimization
- Cache frequently accessed permissions
- Use connection pooling
- Implement lazy loading
- Monitor cache hit rates

## API Reference

### JWT Validator Interface

```go
type JWTValidator interface {
    ValidateTokenLocally(tokenString string) (*types.UserContext, error)
    ValidateTokenLocallyWithContext(ctx context.Context, tokenString string) (*types.UserContext, error)
    ValidateTokenWithFallback(ctx context.Context, tokenString string) (*types.UserContext, error)
    ParseTokenClaims(tokenString string) (jwt.MapClaims, error)
    IsTokenRevoked(tokenString string) bool
    RevokeToken(tokenString string)
}
```

### Service Account Manager Interface

```go
type ServiceAccountManager interface {
    RegisterServiceAccount(serviceID, serviceName string, permissions []string, metadata map[string]string) (*types.ServiceAccount, error)
    GenerateServiceToken(serviceID string, expiry time.Duration) (string, error)
    ValidateServiceToken(tokenString string) (*types.ServiceAccount, error)
    RevokeServiceToken(tokenString string) error
    GetServiceAccount(serviceID string) (*types.ServiceAccount, error)
    DeleteServiceAccount(serviceID string) error
}
```

### Audit Logger Interface

```go
type AuditLogger interface {
    LogAuthEvent(ctx context.Context, eventType types.AuditEventType, userID, reason string, success bool, metadata map[string]interface{}) error
    LogAccessEvent(ctx context.Context, userID, resource, action, resourceID string, success bool, reason string) error
    LogSecurityEvent(ctx context.Context, eventType types.AuditEventType, details map[string]interface{}) error
}
```

## Examples

### Complete Service Setup

```go
func main() {
    // Load configuration
    jwtConfig := loadJWTConfig()
    auditConfig := config.LoadAuditConfig()
    
    // Initialize components
    auditLogger := config.NewAuditLogger("site-service", auditConfig)
    jwtValidator := authutils.NewJWTValidator(jwtConfig, auditLogger)
    serviceManager := authutils.NewServiceAccountManager(jwtConfig.Secret, jwtConfig.Issuer)
    userPropagation := authutils.NewUserContextPropagation(auditLogger)
    
    // Setup hybrid authentication
    hybridAuth := authutils.NewHybridAuthMiddleware(
        jwtValidator,
        serviceManager,
        userPropagation,
        auditLogger,
    )
    
    // Setup RBAC
    rbac := authutils.NewRBACMiddleware("site-service", permissions.SitePermissionMatrix, nil, auditLogger)
    
    // Setup HTTP server
    router := chi.NewRouter()
    router.Use(hybridAuth.HTTPMiddleware)
    router.With(rbac.RequirePermission("site", "read")).Get("/", handleGetSites)
    
    // Setup gRPC server
    grpcServer := grpc.NewServer(
        grpc.UnaryInterceptor(hybridAuth.GRPCUnaryInterceptor()),
        grpc.StreamInterceptor(hybridAuth.GRPCStreamInterceptor()),
    )
    
    // Start servers
    log.Fatal(http.ListenAndServe(":8080", router))
}
```

### Service-to-Service Communication

```go
// Client making request to another service
func callOtherService(ctx context.Context) (*Response, error) {
    // Get service token
    serviceToken, err := serviceManager.GenerateServiceToken("my-service", 1*time.Hour)
    if err != nil {
        return nil, err
    }
    
    // Create gRPC connection with service token
    conn, err := grpc.Dial(
        "other-service:9090",
        grpc.WithUnaryInterceptor(hybridAuth.ClientInterceptor()),
    )
    if err != nil {
        return nil, err
    }
    
    client := NewOtherServiceClient(conn)
    
    // Call with service token in context
    ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+serviceToken)
    return client.DoSomething(ctx, request)
}
```

## Testing

### Unit Tests

```go
func TestJWTValidation(t *testing.T) {
    jwtConfig := &types.JWTConfig{
        Secret:  "test-secret",
        Issuer:  "test-issuer",
    }
    
    validator := authutils.NewJWTValidator(jwtConfig, nil)
    
    // Test valid token
    token := generateValidToken(jwtConfig.Secret, jwtConfig.Issuer)
    userCtx, err := validator.ValidateTokenLocally(token)
    assert.NoError(t, err)
    assert.Equal(t, "user123", userCtx.UserID)
    
    // Test invalid token
    _, err = validator.ValidateTokenLocally("invalid.token")
    assert.Error(t, err)
}
```

### Integration Tests

```go
func TestHybridAuthentication(t *testing.T) {
    // Setup test environment
    jwtValidator := setupTestJWTValidator()
    serviceManager := setupTestServiceManager()
    auditLogger := setupTestAuditLogger()
    
    hybridAuth := authutils.NewHybridAuthMiddleware(
        jwtValidator,
        serviceManager,
        nil,
        auditLogger,
    )
    
    // Test user authentication
    req := httptest.NewRequest("GET", "/", nil)
    req.Header.Set("Authorization", "Bearer "+generateUserToken())
    
    rr := httptest.NewRecorder()
    hybridAuth.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authCtx, ok := authutils.GetAuthContextFromContext(r.Context())
        assert.True(t, ok)
        assert.Equal(t, authutils.AuthTypeUser, authCtx.Type)
    })).ServeHTTP(rr, req)
    
    assert.Equal(t, http.StatusOK, rr.Code)
}
```

## Performance Considerations

### 1. Caching Strategy
- **Token Cache**: Cache validated tokens untuk reduce JWT parsing overhead
- **Permission Cache**: Cache calculated permissions untuk user roles
- **Service Account Cache**: Cache service tokens untuk inter-service calls

### 2. Database Optimization
- Use connection pooling
- Implement query optimization
- Consider read replicas for permission queries

### 3. Network Optimization
- Use gRPC for inter-service communication
- Implement connection reuse
- Consider load balancing

## Troubleshooting

### Common Issues

1. **Token Validation Fails**
   - Check JWT secret consistency
   - Verify token expiration
   - Validate issuer configuration

2. **Permission Denied**
   - Check permission matrix configuration
   - Verify role hierarchy
   - Validate resource ownership

3. **Service Account Issues**
   - Ensure service account registration
   - Check token expiration
   - Validate permission scope

### Debug Mode

```go
// Enable debug logging
auditConfig := config.AuditConfig{
    EnableConsole: true,
    EnableFile:    true,
    FilePath:      "/tmp/auth-debug.log",
}

// Enable cache debugging
permissionCache := cache.NewCacheManager(true, 1*time.Minute, 30*time.Second)
stats := permissionCache.GetCacheStats()
log.Printf("Cache stats: %+v", stats)
```

## Migration Guide

### From Basic JWT to Hybrid Auth

1. **Add Service Account Manager**
```go
// Before
jwtValidator := authutils.NewJWTValidator(config, auditLogger)

// After
serviceManager := authutils.NewServiceAccountManager(config.Secret, config.Issuer)
hybridAuth := authutils.NewHybridAuthMiddleware(jwtValidator, serviceManager, userPropagation, auditLogger)
```

2. **Update Middleware**
```go
// Before
router.Use(jwtMiddleware.RequireAuthentication)

// After
router.Use(hybridAuth.HTTPMiddleware)
```

3. **Update gRPC Server**
```go
// Before
grpcServer := grpc.NewServer()

// After
grpcServer := grpc.NewServer(
    grpc.UnaryInterceptor(hybridAuth.GRPCUnaryInterceptor()),
)
```

## Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For questions and support:
- Create an issue in the repository
- Check the documentation
- Review the examples