package types

import (
	"context"
	"time"
)

type AuditEvent struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	Service    string                 `json:"service"`
	EventType  AuditEventType         `json:"event_type"`
	UserID     string                 `json:"user_id,omitempty"`
	ResourceID string                 `json:"resource_id,omitempty"`
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	IPAddress  string                 `json:"ip_address"`
	UserAgent  string                 `json:"user_agent"`
	Success    bool                   `json:"success"`
	Reason     string                 `json:"reason,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	RequestID  string                 `json:"request_id,omitempty"`
}

type AuditEventType string

const (
	AuditEventLogin              AuditEventType = "login"
	AuditEventLogout             AuditEventType = "logout"
	AuditEventTokenValidated     AuditEventType = "token_validated"
	AuditEventTokenExpired       AuditEventType = "token_expired"
	AuditEventTokenRevoked       AuditEventType = "token_revoked"
	AuditEventAccessGranted      AuditEventType = "access_granted"
	AuditEventAccessDenied       AuditEventType = "access_denied"
	AuditEventPermissionCheck    AuditEventType = "permission_check"
	AuditEventRoleChanged        AuditEventType = "role_changed"
	AuditEventSuspiciousActivity AuditEventType = "suspicious_activity"
)

type AuditLogger interface {
	LogEvent(ctx context.Context, event *AuditEvent) error
	LogAuthEvent(ctx context.Context, eventType AuditEventType, userID, reason string, success bool, metadata map[string]interface{}) error
	LogAccessEvent(ctx context.Context, userID, resource, action, resourceID string, success bool, reason string) error
	LogSecurityEvent(ctx context.Context, eventType AuditEventType, details map[string]interface{}) error
}
