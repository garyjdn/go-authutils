package audit

import (
	"context"

	"github.com/segmentio/kafka-go"
)

type KafkaAuditProducer struct {
	writer *kafka.Writer
}

func NewKafkaProducer(brokers []string) *KafkaAuditProducer {
	writer := &kafka.Writer{
		Addr:     kafka.TCP(brokers...),
		Balancer: &kafka.LeastBytes{},
	}

	return &KafkaAuditProducer{writer: writer}
}

func (p *KafkaAuditProducer) Produce(topic string, message []byte) error {
	err := p.writer.WriteMessages(context.Background(),
		kafka.Message{
			Topic: topic,
			Value: message,
		},
	)
	return err
}

func (p *KafkaAuditProducer) Close() error {
	return p.writer.Close()
}
