// cmd/api/main.go
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/viper"

	// Driver de PostgreSQL (importación necesaria aunque no se use directamente)
	_ "github.com/lib/pq"

	"auth-microservice/pkg/api/http/server"
	"auth-microservice/pkg/infrastructure/email"
)

func main() {
	// Configurar logger
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Iniciando servicio de autenticación - API...")

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

	// Configurar servicio de email
	emailConfig := email.SMTPConfig{
		Host:     viper.GetString("smtp.host"),
		Port:     viper.GetInt("smtp.port"),
		Username: viper.GetString("smtp.username"),
		Password: viper.GetString("smtp.password"),
		From:     viper.GetString("smtp.from"),
	}

	emailSender := email.NewSMTPEmailSender(
		emailConfig,
		viper.GetString("urls.reset_password"),
		viper.GetString("urls.verify_email"),
		viper.GetString("site.name"),
		viper.GetString("site.url"),
		viper.GetString("site.support_email"),
	)

	// Inicializar servicios
	authService := server.InitializeServices(db, emailSender)

	// Configurar router usando la función de server
	router := server.SetupRouter(authService)

	// Iniciar el servidor HTTP
	port := viper.GetString("server.port")
	if port == "" {
		port = "8080" // Puerto por defecto si no está configurado
	}

	// Para desarrollo (localhost)
	srv := &http.Server{
		Addr:         fmt.Sprintf("localhost:%s", port),
		Handler:      router,
		ReadTimeout:  viper.GetDuration("server.read_timeout"),
		WriteTimeout: viper.GetDuration("server.write_timeout"),
		IdleTimeout:  viper.GetDuration("server.idle_timeout"),
	}

	// Para producción, cambiar la configuración del servidor:
	// 1. Cambiar Addr a fmt.Sprintf(":%s", port) para escuchar en todas las interfaces
	// 2. Considerar usar srv.ListenAndServeTLS() para HTTPS
	// 3. Agregar certificados SSL

	// Iniciar el servidor en una goroutine para no bloquear
	go func() {
		log.Printf("Servidor API escuchando en http://localhost:%s", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Error al iniciar el servidor: %v", err)
		}
	}()

	// Capturar señales para shutdown graceful
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Apagando servidor API...")

	// Dar tiempo para que se completen las operaciones en curso
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Error durante el apagado del servidor: %v", err)
	}

	log.Println("Servidor API apagado correctamente")
}
