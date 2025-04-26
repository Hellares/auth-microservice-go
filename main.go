// main.go
package main

import (
	"flag"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

func main() {
	// Configurar logger
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	
	// Permitir elección vía flags
	mode := flag.String("mode", "all", "Modo de ejecución: all, api, worker")
	flag.Parse()

	var apiCmd, workerCmd *exec.Cmd
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Iniciar componentes según el modo
	switch *mode {
	case "all":
		log.Println("Iniciando ambos componentes: API y Worker")
		apiCmd = exec.Command("go", "run", "cmd/api/main.go")
		workerCmd = exec.Command("go", "run", "cmd/worker/main.go")
		
		apiCmd.Stdout = os.Stdout
		apiCmd.Stderr = os.Stderr
		workerCmd.Stdout = os.Stdout
		workerCmd.Stderr = os.Stderr
		
		if err := apiCmd.Start(); err != nil {
			log.Fatalf("Error al iniciar API: %v", err)
		}
		if err := workerCmd.Start(); err != nil {
			log.Fatalf("Error al iniciar Worker: %v", err)
		}
		
		log.Printf("API iniciada con PID: %d", apiCmd.Process.Pid)
		log.Printf("Worker iniciado con PID: %d", workerCmd.Process.Pid)
		
	case "api":
		log.Println("Iniciando solo componente API")
		apiCmd = exec.Command("go", "run", "cmd/api/main.go")
		apiCmd.Stdout = os.Stdout
		apiCmd.Stderr = os.Stderr
		if err := apiCmd.Start(); err != nil {
			log.Fatalf("Error al iniciar API: %v", err)
		}
		log.Printf("API iniciada con PID: %d", apiCmd.Process.Pid)
		
	case "worker":
		log.Println("Iniciando solo componente Worker")
		workerCmd = exec.Command("go", "run", "cmd/worker/main.go")
		workerCmd.Stdout = os.Stdout
		workerCmd.Stderr = os.Stderr
		if err := workerCmd.Start(); err != nil {
			log.Fatalf("Error al iniciar Worker: %v", err)
		}
		log.Printf("Worker iniciado con PID: %d", workerCmd.Process.Pid)
		
	default:
		log.Fatalf("Modo no válido: %s. Use 'all', 'api' o 'worker'", *mode)
	}

	log.Println("Presiona Ctrl+C para terminar todos los componentes")
	
	// Esperar señal de terminación
	<-quit
	log.Println("Señal de terminación recibida. Cerrando componentes...")

	// Terminar procesos si están activos
	if apiCmd != nil && apiCmd.Process != nil {
		log.Printf("Terminando API (PID: %d)...", apiCmd.Process.Pid)
		if err := apiCmd.Process.Signal(syscall.SIGTERM); err != nil {
			log.Printf("Error al terminar API: %v", err)
			// Intentar forzar la terminación si falla el método normal
			if err := apiCmd.Process.Kill(); err != nil {
				log.Printf("Error al forzar terminación de API: %v", err)
			}
		}
	}
	
	if workerCmd != nil && workerCmd.Process != nil {
		log.Printf("Terminando Worker (PID: %d)...", workerCmd.Process.Pid)
		if err := workerCmd.Process.Signal(syscall.SIGTERM); err != nil {
			log.Printf("Error al terminar Worker: %v", err)
			// Intentar forzar la terminación si falla el método normal
			if err := workerCmd.Process.Kill(); err != nil {
				log.Printf("Error al forzar terminación de Worker: %v", err)
			}
		}
	}

	// Esperar a que los procesos terminen
	if apiCmd != nil && apiCmd.Process != nil {
		if err := apiCmd.Wait(); err != nil {
			log.Printf("API terminó con error: %v", err)
		} else {
			log.Println("API terminada correctamente")
		}
	}
	
	if workerCmd != nil && workerCmd.Process != nil {
		if err := workerCmd.Wait(); err != nil {
			log.Printf("Worker terminó con error: %v", err)
		} else {
			log.Println("Worker terminado correctamente")
		}
	}

	log.Println("Todos los componentes han sido terminados.")
}