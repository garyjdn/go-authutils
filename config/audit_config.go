package config

import (
	"os"
	"strings"

	"github.com/garyjdn/go-authutils/audit"
	"github.com/garyjdn/go-authutils/types"
)

type AuditConfig struct {
	EnableConsole bool     `json:"enable_console"`
	EnableFile    bool     `json:"enable_file"`
	EnableKafka   bool     `json:"enable_kafka"`
	FilePath      string   `json:"file_path"`
	KafkaTopic    string   `json:"kafka_topic"`
	KafkaBrokers  []string `json:"kafka_brokers"`
}

func NewAuditLogger(service string, config AuditConfig) types.AuditLogger {
	var backends []audit.AuditLoggerBackend

	if config.EnableConsole {
		backends = append(backends, &audit.ConsoleAuditLogger{})
	}

	if config.EnableFile && config.FilePath != "" {
		backends = append(backends, &audit.FileAuditLogger{FilePath: config.FilePath})
	}

	if config.EnableKafka && len(config.KafkaBrokers) > 0 {
		// Initialize Kafka producer
		producer := audit.NewKafkaProducer(config.KafkaBrokers)
		backends = append(backends, &audit.KafkaAuditLogger{
			Topic:    config.KafkaTopic,
			Producer: producer,
		})
	}

	return audit.NewAuditLogger(service, backends...)
}

func LoadAuditConfig() AuditConfig {
	return AuditConfig{
		EnableConsole: getEnvBool("AUDIT_CONSOLE", true),
		EnableFile:    getEnvBool("AUDIT_FILE", false),
		EnableKafka:   getEnvBool("AUDIT_KAFKA", false),
		FilePath:      getEnv("AUDIT_FILE_PATH", "/var/log/audit.log"),
		KafkaTopic:    getEnv("AUDIT_KAFKA_TOPIC", "audit.events"),
		KafkaBrokers:  getEnvSlice("AUDIT_KAFKA_BROKERS", []string{"kafka:9092"}),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return strings.ToLower(value) == "true"
	}
	return defaultValue
}

func getEnvSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
}
