package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log"

	"github.com/google/uuid"

	"auth-microservice/pkg/application/services"
	"auth-microservice/pkg/domain/entities"
	"auth-microservice/pkg/infrastructure/messaging/rabbitmq" // Importar este paquete
)

// EventHandler maneja los eventos recibidos de RabbitMQ
type EventHandler struct {
	authService services.AuthService
}

// NewEventHandler crea un nuevo manejador de eventos
func NewEventHandler(authService services.AuthService) *EventHandler {
	return &EventHandler{
		authService: authService,
	}
}

// EmpresaCreatedEvent representa un evento de creación de empresa
type EmpresaCreatedEvent struct {
	ID              string `json:"id"`
	RazonSocial     string `json:"razonSocial"`
	NombreComercial string `json:"nombreComercial"`
	RUC             string `json:"ruc"`
	CreadorID       string `json:"creadorId"`
	CreadorDNI      string `json:"creadorDni"`
	CreadorEmail    string `json:"creadorEmail"`
	CreadorNombre   string `json:"creadorNombre"`
	CreadorApellido string `json:"creadorApellido"`
	CreadorTelefono string `json:"creadorTelefono"`
}


func (h *EventHandler) HandleEmpresaCreated(payload []byte) error {
    log.Printf("Recibido evento empresa.created: %s", string(payload))

    // Estructura para manejar el formato de mensaje de NestJS
    type NestEventWrapper struct {
        Pattern string          `json:"pattern"`
        Data    json.RawMessage `json:"data"`
    }

    // Primero intentar deserializar como wrapper de NestJS
    var nestWrapper NestEventWrapper
    if err := json.Unmarshal(payload, &nestWrapper); err != nil {
        log.Printf("Error al deserializar mensaje como wrapper Nest: %v", err)
        
        // Si falla, intentar deserializar directamente
        var event EmpresaCreatedEvent
        if err := json.Unmarshal(payload, &event); err != nil {
            log.Printf("Error al deserializar mensaje como evento directo: %v", err)
            return errors.New("datos insuficientes en el evento")
        }
        
        // Si se puede deserializar directamente, verificar campos críticos
        if event.ID == "" || event.CreadorID == "" {
            log.Printf("Evento sin wrapper tiene datos insuficientes")
            return errors.New("datos insuficientes en el evento")
        }
        
        // Procesar el evento deserializado directamente
        return h.processEmpresaCreatedEvent(event)
    }
    
    // Si es un wrapper de NestJS, deserializar la parte de datos
    var event EmpresaCreatedEvent
    if err := json.Unmarshal(nestWrapper.Data, &event); err != nil {
        log.Printf("Error al deserializar datos dentro del wrapper: %v", err)
        return errors.New("datos insuficientes en el evento")
    }
    
    // Verificar que los campos críticos estén presentes
    if event.ID == "" || event.CreadorID == "" {
        log.Printf("Evento con wrapper tiene datos insuficientes")
        return errors.New("datos insuficientes en el evento")
    }
    
    log.Printf("Evento deserializado: ID=%s, CreadorID=%s, CreadorDNI=%s, CreadorEmail=%s",
        event.ID, event.CreadorID, event.CreadorDNI, event.CreadorEmail)
    
    // Procesar el evento
    return h.processEmpresaCreatedEvent(event)
}

// Método para procesar el evento una vez deserializado correctamente
func (h *EventHandler) processEmpresaCreatedEvent(event EmpresaCreatedEvent) error {
    // Convertir IDs a UUID
    empresaID, err := uuid.Parse(event.ID)
    if err != nil {
        return err
    }

    creadorID, err := uuid.Parse(event.CreadorID)
    if err != nil {
        // Si el creador no existe en el sistema de autenticación, lo creamos
        log.Printf("Creador de empresa no encontrado, creando usuario: %s", event.CreadorEmail)

        // Generar una contraseña temporal
        tempPassword := generateRandomPassword()

        // Registrar al usuario
        user, err := h.authService.Register(
            context.Background(),
            event.CreadorDNI,
            event.CreadorEmail,
            tempPassword,
            event.CreadorNombre,
            event.CreadorApellido,
            event.CreadorTelefono,
        )

        if err != nil {
            return err
        }

        creadorID = user.ID

        // Enviar email con contraseña temporal (implementación pendiente)
        log.Printf("Usuario creado con ID: %s, se debe enviar email con password temporal", user.ID)
    }

    // Asignar rol de administrador de empresa
    return h.authService.CreateEmpresaAdmin(context.Background(), &entities.User{ID: creadorID}, empresaID)
}

// UsuarioCreatedEvent representa un evento de creación de usuario en una empresa
type UsuarioCreatedEvent struct {
	ID        string `json:"id"`
	DNI       string `json:"dni"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Phone     string `json:"phone"`
	EmpresaID string `json:"empresaId"`
	RolID     string `json:"rolId"`
}

// HandleUsuarioCreated maneja el evento de creación de usuario en una empresa
func (h *EventHandler) HandleUsuarioCreated(payload []byte) error {
	var event UsuarioCreatedEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}

	// Validar datos
	if event.DNI == "" || event.Email == "" || event.EmpresaID == "" || event.RolID == "" {
		return errors.New("datos insuficientes en el evento")
	}

	// Convertir IDs a UUID
	empresaID, err := uuid.Parse(event.EmpresaID)
	if err != nil {
		return err
	}

	rolID, err := uuid.Parse(event.RolID)
	if err != nil {
		return err
	}

	// Verificar si el usuario ya existe
	user, err := h.authService.GetUserByDNI(context.Background(), event.DNI)
	if err != nil {
		// Si el usuario no existe, lo creamos
		tempPassword := generateRandomPassword()

		user, err = h.authService.Register(
			context.Background(),
			event.DNI,
			event.Email,
			tempPassword,
			event.FirstName,
			event.LastName,
			event.Phone,
		)

		if err != nil {
			return err
		}

		// Enviar email con contraseña temporal (implementación pendiente)
		log.Printf("Usuario creado con ID: %s, se debe enviar email con password temporal", user.ID)
	}

	// Asignar rol a usuario en la empresa
	return h.authService.AddUserToEmpresa(context.Background(), user.ID, empresaID, rolID)
}

// ClienteCreatedEvent representa un evento de creación de cliente en una empresa
type ClienteCreatedEvent struct {
	ID        string `json:"id"`
	DNI       string `json:"dni"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Phone     string `json:"phone"`
	EmpresaID string `json:"empresaId"`
}

// HandleClienteCreated maneja el evento de creación de cliente en una empresa
func (h *EventHandler) HandleClienteCreated(payload []byte) error {
	var event ClienteCreatedEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}

	// Validar datos
	if event.DNI == "" || event.Email == "" || event.EmpresaID == "" {
		return errors.New("datos insuficientes en el evento")
	}

	// Convertir IDs a UUID
	empresaID, err := uuid.Parse(event.EmpresaID)
	if err != nil {
		return err
	}

	// Buscar rol de cliente
	rolCliente, err := h.authService.GetRoleByName(context.Background(), "CLIENTE")
	if err != nil {
		return err
	}

	// Verificar si el cliente ya existe como usuario
	user, err := h.authService.GetUserByDNI(context.Background(), event.DNI)
	if err != nil {
		// Si el cliente no existe, lo creamos
		tempPassword := generateRandomPassword()

		user, err = h.authService.Register(
			context.Background(),
			event.DNI,
			event.Email,
			tempPassword,
			event.FirstName,
			event.LastName,
			event.Phone,
		)

		if err != nil {
			return err
		}

		// Enviar email con contraseña temporal (implementación pendiente)
		log.Printf("Cliente creado con ID: %s, se debe enviar email con password temporal", user.ID)
	}

	// Asignar rol de cliente en la empresa
	return h.authService.AddUserToEmpresa(context.Background(), user.ID, empresaID, rolCliente.ID)
}

// generateRandomPassword genera una contraseña aleatoria
func generateRandomPassword() string {
	// Implementación simple para ejemplo. En producción, usar algo más seguro.
	return uuid.New().String()[:8]
}

// RegisterEventHandlers registra todos los manejadores de eventos
func RegisterEventHandlers(eventBus rabbitmq.EventBus, handler *EventHandler) error {
	// Suscribirse a eventos de creación de empresa
	if err := eventBus.Subscribe("empresa.created", handler.HandleEmpresaCreated); err != nil {
		return err
	}

	// Suscribirse a eventos de creación de usuario
	if err := eventBus.Subscribe("usuario.created", handler.HandleUsuarioCreated); err != nil {
		return err
	}

	// Suscribirse a eventos de creación de cliente
	if err := eventBus.Subscribe("cliente.created", handler.HandleClienteCreated); err != nil {
		return err
	}

	return nil
}
