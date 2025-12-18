package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/garyjdn/go-authutils/types"
	"github.com/google/uuid"
)

// Multiple audit logger implementations
type auditLogger struct {
	service string
	loggers []AuditLoggerBackend
}

type AuditLoggerBackend interface {
	Write(ctx context.Context, event *types.AuditEvent) error
}

// Console logger untuk development
type ConsoleAuditLogger struct{}

func (l *ConsoleAuditLogger) Write(ctx context.Context, event *types.AuditEvent) error {
	eventJSON, _ := json.Marshal(event)
	log.Printf("[AUDIT] %s", string(eventJSON))
	return nil
}

// File logger untuk production
type FileAuditLogger struct {
	FilePath string
}

func (l *FileAuditLogger) Write(ctx context.Context, event *types.AuditEvent) error {
	file, err := os.OpenFile(l.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	eventJSON, _ := json.Marshal(event)
	_, err = file.WriteString(fmt.Sprintf("%s\n", string(eventJSON)))
	return err
}

// Kafka logger untuk distributed systems
type KafkaAuditLogger struct {
	Topic    string
	Producer KafkaProducer
}

type KafkaProducer interface {
	Produce(topic string, message []byte) error
}

func (l *KafkaAuditLogger) Write(ctx context.Context, event *types.AuditEvent) error {
	eventJSON, _ := json.Marshal(event)
	return l.Producer.Produce(l.Topic, eventJSON)
}

// Main audit logger implementation
func NewAuditLogger(service string, backends ...AuditLoggerBackend) types.AuditLogger {
	return &auditLogger{
		service: service,
		loggers: backends,
	}
}

func (l *auditLogger) LogEvent(ctx context.Context, event *types.AuditEvent) error {
	event.ID = uuid.New().String()
	event.Timestamp = time.Now()
	event.Service = l.service

	// Extract request ID dari context jika ada
	if reqID := ctx.Value("request_id"); reqID != nil {
		event.RequestID = reqID.(string)
	}

	for _, logger := range l.loggers {
		if err := logger.Write(ctx, event); err != nil {
			// Log error tapi jangan gagalkan proses
			log.Printf("Failed to write audit event: %v", err)
		}
	}

	return nil
}

func (l *auditLogger) LogAuthEvent(ctx context.Context, eventType types.AuditEventType, userID, reason string, success bool, metadata map[string]interface{}) error {
	event := &types.AuditEvent{
		EventType: eventType,
		UserID:    userID,
		Success:   success,
		Reason:    reason,
		Metadata:  metadata,
	}

	return l.LogEvent(ctx, event)
}

func (l *auditLogger) LogAccessEvent(ctx context.Context, userID, resource, action, resourceID string, success bool, reason string) error {
	event := &types.AuditEvent{
		EventType:  types.AuditEventAccessGranted,
		UserID:     userID,
		ResourceID: resourceID,
		Action:     action,
		Resource:   resource,
		Success:    success,
		Reason:     reason,
	}

	if !success {
		event.EventType = types.AuditEventAccessDenied
	}

	return l.LogEvent(ctx, event)
}

func (l *auditLogger) LogSecurityEvent(ctx context.Context, eventType types.AuditEventType, details map[string]interface{}) error {
	event := &types.AuditEvent{
		EventType: eventType,
		Metadata:  details,
	}

	return l.LogEvent(ctx, event)
}
