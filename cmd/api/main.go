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

	// Inicializar servicios
	authService := server.InitializeServices(db)

	// Inicializar router y handlers
	router := server.SetupRouter(authService)

	// Iniciar el servidor HTTP
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%s", viper.GetString("server.port")),
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Iniciar el servidor en una goroutine para no bloquear
	go func() {
		log.Printf("Servidor API escuchando en %s", srv.Addr)
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