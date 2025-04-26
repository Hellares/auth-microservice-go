// pkg/infrastructure/messaging/rabbitmq/rabbitmq.go
package rabbitmq

import (
	"context"
	"encoding/json"
	"log"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// EventBus representa la interfaz para publicar y consumir eventos
type EventBus interface {
	Publish(ctx context.Context, routingKey string, event interface{}) error
	Subscribe(routingKey string, handler func([]byte) error) error
	Close() error
}

// RabbitMQEventBus implementa EventBus con RabbitMQ
type RabbitMQEventBus struct {
	conn         *amqp.Connection
	channel      *amqp.Channel
	exchangeName string
	queueName    string
}

// NewRabbitMQEventBus crea una nueva instancia de RabbitMQEventBus
func NewRabbitMQEventBus(url, exchangeName, queueName string) (*RabbitMQEventBus, error) {
	// Conectar a RabbitMQ
	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, err
	}

	// Crear canal
	channel, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Declarar exchange
	err = channel.ExchangeDeclare(
		exchangeName, // nombre
		"topic",      // tipo
		true,         // durable
		false,        // auto-delete
		false,        // internal
		false,        // no-wait
		nil,          // arguments
	)
	if err != nil {
		channel.Close()
		conn.Close()
		return nil, err
	}

	// Declarar cola
	_, err = channel.QueueDeclare(
		queueName, // nombre
		true,      // durable
		false,     // delete when unused
		false,     // exclusive
		false,     // no-wait
		nil,       // arguments
	)
	if err != nil {
		channel.Close()
		conn.Close()
		return nil, err
	}

	return &RabbitMQEventBus{
		conn:         conn,
		channel:      channel,
		exchangeName: exchangeName,
		queueName:    queueName,
	}, nil
}

// Publish publica un evento en RabbitMQ
func (eb *RabbitMQEventBus) Publish(ctx context.Context, routingKey string, event interface{}) error {
	// Convertir evento a JSON
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}

	// Publicar mensaje
	return eb.channel.PublishWithContext(
		ctx,
		eb.exchangeName, // exchange
		routingKey,      // routing key
		false,           // mandatory
		false,           // immediate
		amqp.Publishing{
			ContentType:  "application/json",
			DeliveryMode: amqp.Persistent,
			Timestamp:    time.Now(),
			Body:         body,
		},
	)
}

// Subscribe se suscribe a eventos con una clave de enrutamiento específica
func (eb *RabbitMQEventBus) Subscribe(routingKey string, handler func([]byte) error) error {
	// Enlazar cola a exchange con routing key
	err := eb.channel.QueueBind(
		eb.queueName,    // queue name
		routingKey,      // routing key
		eb.exchangeName, // exchange
		false,
		nil,
	)
	if err != nil {
		return err
	}

	// Consumir mensajes
	msgs, err := eb.channel.Consume(
		eb.queueName, // queue
		"",           // consumer
		false,        // auto-ack
		false,        // exclusive
		false,        // no-local
		false,        // no-wait
		nil,          // args
	)
	if err != nil {
		return err
	}

	// Procesar mensajes en goroutine
	go func() {
		for msg := range msgs {
			err := handler(msg.Body)
			if err != nil {
				log.Printf("Error procesando mensaje: %v", err)
				// Rechazar mensaje para que sea re-encolado
				msg.Nack(false, true)
			} else {
				// Confirmar mensaje
				msg.Ack(false)
			}
		}
	}()

	return nil
}

// Close cierra la conexión a RabbitMQ
func (eb *RabbitMQEventBus) Close() error {
	if err := eb.channel.Close(); err != nil {
		return err
	}
	return eb.conn.Close()
}