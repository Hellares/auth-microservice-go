// cmd/worker/main.go
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/spf13/viper"

	"auth-microservice/pkg/api/http/server"
	// "auth-microservice/pkg/application/services"
	"auth-microservice/pkg/infrastructure/messaging/rabbitmq"
	msgHandlers "auth-microservice/pkg/infrastructure/messaging/handlers"
)

func main() {
	// Configurar logger
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Iniciando servicio de autenticación - Worker...")

	// Cargar configuración
	if err := server.LoadConfig(); err != nil {
		log.Fatalf("Error al cargar la configuración: %v", err)
	}

	// Conectar a la base de datos
	db, err := server.ConnectDB()
	if err != nil {
		log.Fatalf("Error al conectar a la base de datos: %v", err)
	}
	defer db.Close()

	// Inicializar servicios
	authService := server.InitializeServices(db)

	// Conectar a RabbitMQ
	eventBus, err := connectRabbitMQ()
	if err != nil {
		log.Fatalf("Error al conectar a RabbitMQ: %v", err)
	}
	defer eventBus.Close()

	// Inicializar manejadores de eventos
	eventHandler := msgHandlers.NewEventHandler(authService)
	if err := msgHandlers.RegisterEventHandlers(eventBus, eventHandler); err != nil {
		log.Fatalf("Error al registrar manejadores de eventos: %v", err)
	}

	log.Println("Worker iniciado, escuchando eventos...")

	// Configurar limpieza periódica de tokens y sesiones expiradas
	go runPeriodicCleanup(db)

	// Capturar señales para shutdown graceful
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Apagando worker...")

	log.Println("Worker apagado correctamente")
}

// connectRabbitMQ establece la conexión a RabbitMQ
func connectRabbitMQ() (*rabbitmq.RabbitMQEventBus, error) {
	return rabbitmq.NewRabbitMQEventBus(
		viper.GetString("rabbitmq.url"),
		viper.GetString("rabbitmq.exchange"),
		viper.GetString("rabbitmq.queue"),
	)
}

// runPeriodicCleanup ejecuta tareas de limpieza periódicamente
func runPeriodicCleanup(db *sqlx.DB) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			log.Println("Ejecutando limpieza periódica de datos...")
			
			// Crear contexto con timeout
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			
			// Limpiar tokens de verificación expirados
			if err := cleanupExpiredVerificationTokens(ctx, db); err != nil {
				log.Printf("Error al limpiar tokens de verificación expirados: %v", err)
			}
			
			// Limpiar sesiones expiradas
			if err := cleanupExpiredSessions(ctx, db); err != nil {
				log.Printf("Error al limpiar sesiones expiradas: %v", err)
			}
			
			cancel()
		}
	}
}

// cleanupExpiredVerificationTokens limpia los tokens de verificación expirados
func cleanupExpiredVerificationTokens(ctx context.Context, db *sqlx.DB) error {
	query := `DELETE FROM verification_tokens WHERE expires_at < NOW()`
	_, err := db.ExecContext(ctx, query)
	if err != nil {
		return err
	}
	log.Println("Tokens de verificación expirados eliminados")
	return nil
}

// cleanupExpiredSessions limpia las sesiones expiradas
func cleanupExpiredSessions(ctx context.Context, db *sqlx.DB) error {
	query := `DELETE FROM sessions WHERE expires_at < NOW()`
	_, err := db.ExecContext(ctx, query)
	if err != nil {
		return err
	}
	log.Println("Sesiones expiradas eliminadas")
	return nil
}