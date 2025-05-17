package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"auth-microservice/pkg/application/services"
	"auth-microservice/pkg/domain/entities"
	// "auth-microservice/pkg/domain/entities"
)

// Response es la estructura para las respuestas HTTP
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// AuthHandler maneja las peticiones HTTP relacionadas con autenticación
type AuthHandler struct {
	authService services.AuthService
}

type PaginatedResponse struct {
    Success    bool                   `json:"success"`
    Message    string                 `json:"message,omitempty"`
    Data       interface{}            `json:"data,omitempty"`
    Pagination map[string]interface{} `json:"pagination,omitempty"`
    Error      string                 `json:"error,omitempty"`
}

// Estructura para errores más detallados
type ErrorDetail struct {
    Code    string              `json:"code"`
    Message string              `json:"message"`
    Field   string              `json:"field,omitempty"`
    Meta    map[string]interface{} `json:"meta,omitempty"`
}

// Función helper para responder con JSON paginado
func respondWithPaginatedJSON(w http.ResponseWriter, status int, response PaginatedResponse) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    json.NewEncoder(w).Encode(response)
}

// Función para responder con error paginado
func respondWithPaginatedError(w http.ResponseWriter, status int, message string) {
    response := PaginatedResponse{
        Success: false,
        Error:   message,
        Data:    nil,
        Pagination: nil,
    }
    respondWithPaginatedJSON(w, status, response)
}

// Función para errores de validación
func respondWithValidationError(w http.ResponseWriter, errors []ErrorDetail) {
    response := PaginatedResponse{
        Success: false,
        Error:   "Error de validación",
        Data: map[string]interface{}{
            "errors": errors,
        },
    }
    respondWithPaginatedJSON(w, http.StatusBadRequest, response)
}

// Función para validar parámetros de paginación
func validatePaginationParams(pageStr, limitStr string) (int, int, []ErrorDetail) {
    var errors []ErrorDetail
    page := 1
    limit := 10
    
    if pageStr != "" {
        p, err := strconv.Atoi(pageStr)
        if err != nil {
            errors = append(errors, ErrorDetail{
                Code:    "INVALID_PAGE",
                Message: "El parámetro 'page' debe ser un número",
                Field:   "page",
            })
        } else if p <= 0 {
            errors = append(errors, ErrorDetail{
                Code:    "PAGE_OUT_OF_RANGE",
                Message: "El número de página debe ser mayor a 0",
                Field:   "page",
                Meta: map[string]interface{}{
                    "min": 1,
                },
            })
        } else {
            page = p
        }
    }
    
    if limitStr != "" {
        l, err := strconv.Atoi(limitStr)
        if err != nil {
            errors = append(errors, ErrorDetail{
                Code:    "INVALID_LIMIT",
                Message: "El parámetro 'limit' debe ser un número",
                Field:   "limit",
            })
        } else if l <= 0 {
            errors = append(errors, ErrorDetail{
                Code:    "LIMIT_TOO_SMALL",
                Message: "El límite debe ser mayor a 0",
                Field:   "limit",
                Meta: map[string]interface{}{
                    "min": 1,
                },
            })
        } else if l > 100 {
            errors = append(errors, ErrorDetail{
                Code:    "LIMIT_TOO_LARGE",
                Message: "El límite no puede ser mayor a 100",
                Field:   "limit",
                Meta: map[string]interface{}{
                    "max": 100,
                },
            })
        } else {
            limit = l
        }
    }
    
    return page, limit, errors
}

// Función para validar UUID
func validateUUID(value, fieldName string) *ErrorDetail {
    if _, err := uuid.Parse(value); err != nil {
        return &ErrorDetail{
            Code:    "INVALID_UUID",
            Message: fmt.Sprintf("El %s debe ser un UUID válido", fieldName),
            Field:   fieldName,
        }
    }
    return nil
}

// NewAuthHandler crea un nuevo handler de autenticación
func NewAuthHandler(authService services.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

// RegisterRoutes registra las rutas para el handler
func (h *AuthHandler) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/users/search", h.FindUserByIdentifier).Methods("GET")
	router.HandleFunc("/users/find", h.FindUserByIdentifier).Methods("GET")
    router.HandleFunc("/users", h.ListAllUsers).Methods("GET")

	router.HandleFunc("/register", h.Register).Methods("POST")
	router.HandleFunc("/login", h.Login).Methods("POST")
	router.HandleFunc("/verify-email", h.VerifyEmail).Methods("GET", "POST")
	router.HandleFunc("/request-password-reset", h.RequestPasswordReset).Methods("POST")
	router.HandleFunc("/reset-password", h.ResetPassword).Methods("POST")
	router.HandleFunc("/change-password", h.ChangePassword).Methods("POST")
	router.HandleFunc("/me", h.GetCurrentUser).Methods("GET")
	router.HandleFunc("/users/{id}", h.GetUser).Methods("GET")
	router.HandleFunc("/users/{id}/roles", h.GetUserRoles).Methods("GET")
	router.HandleFunc("/users/{id}/permissions", h.GetUserPermissions).Methods("GET")

	router.HandleFunc("/users/me/empresas", h.GetCurrentUserEmpresas).Methods("GET")
    router.HandleFunc("/users/{id}/empresas", h.GetUserEmpresas).Methods("GET")  // Añadido para obtener empresas de un usuario logueado

	
    router.HandleFunc("/users/{id}/empresas/{empresaId}/add-as-client", h.AddClientToEmpresa).Methods("POST")

	router.HandleFunc("/users/me/all-permissions", h.GetCurrentUserAllPermissions).Methods("GET")
	router.HandleFunc("/users/{id}/all-permissions", h.GetAllUserPermissions).Methods("GET")
	router.HandleFunc("/users/empresa/{empresaId}", h.GetUsersByEmpresa).Methods("GET")
    router.HandleFunc("/empresa/{empresaId}/all-users", h.ListAllUsersInEmpresa).Methods("GET")
		 //Queries("page", "{page:[0-9]*}", "limit", "{limit:[0-9]*}", "role", "{role:.*}") // Añadido para obtener usuarios por empresa

}

// Register maneja el registro de nuevos usuarios
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	// Estructura para la petición
	var req struct {
		DNI       string `json:"dni"`
		Email     string `json:"email"`
		Password  string `json:"password"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
		Phone     string `json:"phone,omitempty"`
	}

	// Decodificar JSON
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Petición inválida")
		return
	}

	// Validar datos
	if req.DNI == "" || req.Email == "" || req.Password == "" || req.FirstName == "" || req.LastName == "" {
		respondWithError(w, http.StatusBadRequest, "Campos requeridos faltantes")
		return
	}

	// Registrar usuario
	user, err := h.authService.Register(r.Context(), req.DNI, req.Email, req.Password, req.FirstName, req.LastName, req.Phone)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Responder con éxito
	respondWithJSON(w, http.StatusCreated, Response{
		Success: true,
		Message: "Usuario registrado con éxito",
		Data:    user,
	})
}

// Login maneja el inicio de sesión
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	// Estructura para la petición
	var req struct {
		DNI      string `json:"dni"`
		Password string `json:"password"`
	}

	// Decodificar JSON
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Petición inválida")
		return
	}

	// Validar datos
	if req.DNI == "" || req.Password == "" {
		respondWithError(w, http.StatusBadRequest, "DNI y contraseña son requeridos")
		return
	}

	// Iniciar sesión
	token, err := h.authService.Login(r.Context(), req.DNI, req.Password)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Responder con token
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Data: map[string]string{
			"token": token,
		},
	})
}

// VerifyEmail verifica el email de un usuario
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var token string

	// Obtener token dependiendo del método HTTP
	if r.Method == "GET" {
		token = r.URL.Query().Get("token")
	} else {
		// Para POST, decodificar JSON del body
		var req struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondWithError(w, http.StatusBadRequest, "Petición inválida")
			return
		}
		token = req.Token
	}

	// Validar token
	if token == "" {
		respondWithError(w, http.StatusBadRequest, "Token requerido")
		return
	}

	// Verificar email
	err := h.authService.VerifyEmail(r.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Si es GET, redirigir a una página de éxito
	if r.Method == "GET" {
		http.Redirect(w, r, "/email-verified.html", http.StatusSeeOther)
		return
	}

	// Para POST, responder con JSON
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Email verificado con éxito",
	})
}

// RequestPasswordReset solicita un reseteo de contraseña
func (h *AuthHandler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	// Estructura para la petición
	var req struct {
		Email string `json:"email"`
	}

	// Decodificar JSON
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Petición inválida")
		return
	}

	// Validar datos
	if req.Email == "" {
		respondWithError(w, http.StatusBadRequest, "Email requerido")
		return
	}

	// Solicitar reseteo
	token, err := h.authService.RequestPasswordReset(r.Context(), req.Email)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Responder con éxito
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Solicitud de reseteo de contraseña enviada",
		Data: map[string]string{
			"token": token.Token,
		},
	})
}

// ResetPassword resetea la contraseña
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	// Estructura para la petición
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"newPassword"`
	}

	// Decodificar JSON
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Petición inválida")
		return
	}

	// Validar datos
	if req.Token == "" || req.NewPassword == "" {
		respondWithError(w, http.StatusBadRequest, "Token y nueva contraseña requeridos")
		return
	}

	// Resetear contraseña
	err = h.authService.ResetPassword(r.Context(), req.Token, req.NewPassword)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Responder con éxito
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Contraseña restablecida con éxito",
	})
}

// ChangePassword cambia la contraseña de un usuario autenticado
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	// Obtener token del encabezado
	token := extractToken(r)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "No autorizado")
		return
	}

	// Verificar token
	claims, err := h.authService.VerifyToken(r.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Estructura para la petición
	var req struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}

	// Decodificar JSON
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Petición inválida")
		return
	}

	// Validar datos
	if req.CurrentPassword == "" || req.NewPassword == "" {
		respondWithError(w, http.StatusBadRequest, "Contraseña actual y nueva requeridas")
		return
	}

	// Obtener ID del usuario del token
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error en el token")
		return
	}

	// Cambiar contraseña
	err = h.authService.ChangePassword(r.Context(), userID, req.CurrentPassword, req.NewPassword)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Responder con éxito
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Contraseña cambiada con éxito",
	})
}

// GetCurrentUser obtiene el usuario actual basado en el token
func (h *AuthHandler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	// Obtener token del encabezado
	token := extractToken(r)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "No autorizado")
		return
	}

	// Verificar token
	claims, err := h.authService.VerifyToken(r.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Obtener ID del usuario del token
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error en el token")
		return
	}

	// Obtener usuario
	user, err := h.authService.GetUserByID(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	// Responder con usuario
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    user,
	})
}

// GetUser obtiene un usuario por su ID
func (h *AuthHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	// Obtener token del encabezado
	token := extractToken(r)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "No autorizado")
		return
	}

	// Verificar token
	_, err := h.authService.VerifyToken(r.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Obtener ID del usuario de la URL
	vars := mux.Vars(r)
	userID, err := uuid.Parse(vars["id"])
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "ID de usuario inválido")
		return
	}

	// Obtener usuario
	user, err := h.authService.GetUserByID(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	// Responder con usuario
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    user,
	})
}

// GetUserRoles obtiene los roles de un usuario en una empresa
func (h *AuthHandler) GetUserRoles(w http.ResponseWriter, r *http.Request) {
	// Obtener token del encabezado
	token := extractToken(r)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "No autorizado")
		return
	}

	// Verificar token
	_, err := h.authService.VerifyToken(r.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Obtener ID del usuario de la URL
	vars := mux.Vars(r)
	userID, err := uuid.Parse(vars["id"])
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "ID de usuario inválido")
		return
	}

	// Obtener ID de la empresa de los query params
	empresaIDStr := r.URL.Query().Get("empresaId")
	if empresaIDStr == "" {
		respondWithError(w, http.StatusBadRequest, "ID de empresa requerido")
		return
	}

	empresaID, err := uuid.Parse(empresaIDStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "ID de empresa inválido")
		return
	}

	// Obtener roles del usuario
	roles, err := h.authService.GetUserRoles(r.Context(), userID, empresaID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Responder con roles
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    roles,
	})
}

// func (h *AuthHandler) GetCurrentUserRoles(w http.ResponseWriter, r *http.Request) {
//     // Obtener token del encabezado
//     token := extractToken(r)
//     if token == "" {
//         respondWithError(w, http.StatusUnauthorized, "No autorizado")
//         return
//     }

//     // Verificar token
//     claims, err := h.authService.VerifyToken(r.Context(), token)
//     if err != nil {
//         respondWithError(w, http.StatusUnauthorized, err.Error())
//         return
//     }

//     // Obtener ID del usuario del token
//     userID, err := uuid.Parse(claims.UserID)
//     if err != nil {
//         respondWithError(w, http.StatusInternalServerError, "Error en el token")
//         return
//     }

//     // Obtener ID de la empresa de los query params (opcional)
//     empresaIDStr := r.URL.Query().Get("empresaId")
    
//     var userRoles []*entities.Role
    
//     if empresaIDStr != "" {
//         // Si se especifica empresa, obtener roles de esa empresa
//         empresaID, err := uuid.Parse(empresaIDStr)
//         if err != nil {
//             respondWithError(w, http.StatusBadRequest, "ID de empresa inválido")
//             return
//         }
        
//         userRoles, err = h.authService.GetUserRoles(r.Context(), userID, empresaID)
//         if err != nil {
//             respondWithError(w, http.StatusInternalServerError, err.Error())
//             return
//         }
//     } else {
//         // Si no se especifica empresa, obtener TODOS los roles (sistema + empresas)
//         userRoles, err = h.authService.GetAllUserRoles(r.Context(), userID)
//         if err != nil {
//             respondWithError(w, http.StatusInternalServerError, err.Error())
//             return
//         }
//     }

//     // Responder con los roles
//     respondWithJSON(w, http.StatusOK, Response{
//         Success: true,
//         Data:    userRoles,
//     })
// }

// GetUserPermissions obtiene los permisos de un usuario en una empresa
func (h *AuthHandler) GetUserPermissions(w http.ResponseWriter, r *http.Request) {
	// Obtener token del encabezado
	token := extractToken(r)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "No autorizado")
		return
	}

	// Verificar token
	_, err := h.authService.VerifyToken(r.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Obtener ID del usuario de la URL
	vars := mux.Vars(r)
	userID, err := uuid.Parse(vars["id"])
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "ID de usuario inválido")
		return
	}

	// Obtener ID de la empresa de los query params
	empresaIDStr := r.URL.Query().Get("empresaId")
	if empresaIDStr == "" {
		respondWithError(w, http.StatusBadRequest, "ID de empresa requerido")
		return
	}

	empresaID, err := uuid.Parse(empresaIDStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "ID de empresa inválido")
		return
	}

	// Obtener los permisos que queremos comprobar de los query params
	perms := r.URL.Query()["permission"]

	// Mapa para almacenar los resultados
	permResults := make(map[string]bool)

	// Comprobar cada permiso
	for _, perm := range perms {
		hasPermission, err := h.authService.HasPermission(r.Context(), userID, empresaID, perm)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}
		permResults[perm] = hasPermission
	}

	// Responder con los resultados
	respondWithJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    permResults,
	})
}

func (h *AuthHandler) GetAllUserPermissions(w http.ResponseWriter, r *http.Request) {
    // Obtener token del encabezado
    token := extractToken(r)
    if token == "" {
        respondWithError(w, http.StatusUnauthorized, "No autorizado")
        return
    }

    // Verificar token
    claims, err := h.authService.VerifyToken(r.Context(), token)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, err.Error())
        return
    }

    // Obtener ID del usuario de la URL
    vars := mux.Vars(r)
    userID, err := uuid.Parse(vars["id"])
    if err != nil {
        respondWithError(w, http.StatusBadRequest, "ID de usuario inválido")
        return
    }

    // Verificar que el usuario puede ver esta información
    // if claims.UserID != userID.String() {
    //     // Si no es el mismo usuario, verificar permisos de admin
    //     currentUserID := uuid.MustParse(claims.UserID)
    //     hasAdminPermission, _ := h.authService.HasPermission(r.Context(), currentUserID, uuid.Nil, "SUPER_ADMIN")
    //     if !hasAdminPermission {
    //         respondWithError(w, http.StatusForbidden, "No autorizado para ver permisos de otro usuario")
    //         return
    //     }
    // }

	if claims.UserID != userID.String() {
        currentUserID := uuid.MustParse(claims.UserID)
        
        // Primero verificar si es SUPER_ADMIN del sistema
        isSuperAdmin, err := h.authService.HasSystemRole(r.Context(), currentUserID, "SUPER_ADMIN")
        if err != nil {
            log.Printf("Error verificando rol de sistema: %v", err)
            respondWithError(w, http.StatusInternalServerError, "Error verificando permisos")
            return
        }
        
        if !isSuperAdmin {
            respondWithError(w, http.StatusForbidden, "No autorizado para ver permisos de otro usuario")
            return
        }
    }

    // Obtener ID de la empresa de los query params
    empresaIDStr := r.URL.Query().Get("empresaId")
    if empresaIDStr == "" {
        respondWithError(w, http.StatusBadRequest, "ID de empresa requerido")
        return
    }

    empresaID, err := uuid.Parse(empresaIDStr)
    if err != nil {
        respondWithError(w, http.StatusBadRequest, "ID de empresa inválido")
        return
    }

    // Obtener todos los roles del usuario en la empresa
    roles, err := h.authService.GetUserRoles(r.Context(), userID, empresaID)
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, err.Error())
        return
    }

    // Estructura para la respuesta
    type UserPermissionsResponse struct {
        Roles       []string          `json:"roles"`
        Permissions map[string]bool   `json:"permissions"`
    }

    response := UserPermissionsResponse{
        Roles:       make([]string, 0),
        Permissions: make(map[string]bool),
    }

    // Añadir roles y permisos
    for _, role := range roles {
        response.Roles = append(response.Roles, role.Name)
        
        // Usar el nuevo método para obtener permisos
        permissions, err := h.authService.GetPermissionsByRole(r.Context(), role.ID)
        if err != nil {
            log.Printf("Error obteniendo permisos del rol %s: %v", role.Name, err)
            continue
        }
        
        for _, permission := range permissions {
            response.Permissions[permission.Name] = true
        }
    }

    // Responder con los datos completos
    respondWithJSON(w, http.StatusOK, Response{
        Success: true,
        Data:    response,
    })
}

func (h *AuthHandler) GetCurrentUserAllPermissions(w http.ResponseWriter, r *http.Request) {
    // Obtener token del encabezado
    token := extractToken(r)
    if token == "" {
        respondWithError(w, http.StatusUnauthorized, "No autorizado")
        return
    }

    // Verificar token
    claims, err := h.authService.VerifyToken(r.Context(), token)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, err.Error())
        return
    }

    // Obtener ID del usuario del token
    userID, err := uuid.Parse(claims.UserID)
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Error en el token")
        return
    }

    // Obtener ID de la empresa de los query params
    empresaIDStr := r.URL.Query().Get("empresaId")
    if empresaIDStr == "" {
        respondWithError(w, http.StatusBadRequest, "ID de empresa requerido")
        return
    }

    empresaID, err := uuid.Parse(empresaIDStr)
    if err != nil {
        respondWithError(w, http.StatusBadRequest, "ID de empresa inválido")
        return
    }

    // Obtener todos los roles del usuario en la empresa
    roles, err := h.authService.GetUserRoles(r.Context(), userID, empresaID)
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, err.Error())
        return
    }

    // Estructura para la respuesta
    type UserPermissionsResponse struct {
        Roles       []string          `json:"roles"`
        Permissions map[string]bool   `json:"permissions"`
    }

    response := UserPermissionsResponse{
        Roles:       make([]string, 0),
        Permissions: make(map[string]bool),
    }

    // Añadir roles y permisos
    for _, role := range roles {
        response.Roles = append(response.Roles, role.Name)
        
        // Usar el método del servicio para obtener permisos
        permissions, err := h.authService.GetPermissionsByRole(r.Context(), role.ID)
        if err != nil {
            log.Printf("Error obteniendo permisos del rol %s: %v", role.Name, err)
            continue
        }
        
        for _, permission := range permissions {
            response.Permissions[permission.Name] = true
        }
    }

    // Responder con los datos completos
    respondWithJSON(w, http.StatusOK, Response{
        Success: true,
        Data:    response,
    })
}

// GetCurrentUserEmpresas obtiene las empresas del usuario autenticado
func (h *AuthHandler) GetCurrentUserEmpresas(w http.ResponseWriter, r *http.Request) {
    // Obtener token del encabezado
    token := extractToken(r)
    if token == "" {
        respondWithError(w, http.StatusUnauthorized, "No autorizado")
        return
    }

    // Verificar token
    claims, err := h.authService.VerifyToken(r.Context(), token)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, err.Error())
        return
    }

    // Obtener ID del usuario del token
    userID, err := uuid.Parse(claims.UserID)
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Error en el token")
        return
    }

    // Obtener empresas del usuario
    empresasIDs, err := h.authService.GetUserEmpresas(r.Context(), userID)
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, err.Error())
        return
    }

    // Responder con las empresas
    respondWithJSON(w, http.StatusOK, Response{
        Success: true,
        Data:    empresasIDs,
    })
}


// GetUserEmpresas obtiene las empresas de un usuario específico por su ID
// Esta función es similar a GetCurrentUserEmpresas, pero permite obtener empresas de otros usuarios
//! se implementa para ver la lista de empresas y poder tercerizar servicios Aun no implementado
func (h *AuthHandler) GetUserEmpresas(w http.ResponseWriter, r *http.Request) {
    // Obtener token del encabezado
    token := extractToken(r)
    if token == "" {
        respondWithError(w, http.StatusUnauthorized, "No autorizado")
        return
    }

    // Verificar token
    claims, err := h.authService.VerifyToken(r.Context(), token)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, err.Error())
        return
    }

    // Obtener ID del usuario de la URL
    vars := mux.Vars(r)
    userID, err := uuid.Parse(vars["id"])
    if err != nil {
        respondWithError(w, http.StatusBadRequest, "ID de usuario inválido")
        return
    }

    // Verificar si el usuario tiene permisos para ver esta información
    // 1. Si el usuario solicita sus propias empresas, permitir
    // 2. Si el usuario tiene permisos administrativos, permitir
    requestedUserIDStr := userID.String()
	currentUserID := uuid.MustParse(claims.UserID)

    // Si no es el mismo usuario, verificar permisos
    if claims.UserID != requestedUserIDStr {
        // Verificamos diferentes tipos de permisos que podrían aplicar
        
        // 1. SUPER_ADMIN - Puede ver todas las empresas de cualquier usuario
        hasSuperAdminPermission, _ := h.authService.HasPermission(r.Context(), currentUserID, uuid.Nil, "SUPER_ADMIN")
        
        // 2. EMPRESA_ADMIN - Puede administrar usuarios
        hasAdminUsersPermission, _ := h.authService.HasPermission(r.Context(), currentUserID, uuid.Nil, "EMPRESA_ADMIN")
        
        // 3. VIEW_PARTNER_EMPRESAS - Permiso específico para ver empresas de potenciales socios/terceros
        hasViewPartnerPermission, _ := h.authService.HasPermission(r.Context(), currentUserID, uuid.Nil, "VIEW_PARTNER_EMPRESAS")
        
        // Si no tiene ninguno de estos permisos, denegar acceso
        if !hasSuperAdminPermission && !hasAdminUsersPermission && !hasViewPartnerPermission {
            respondWithError(w, http.StatusForbidden, "No tienes permiso para ver las empresas de este usuario")
            return
        }
    }

    // Obtener empresas del usuario
    empresasIDs, err := h.authService.GetUserEmpresas(r.Context(), userID)
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, err.Error())
        return
    }

    // Responder con las empresas
    respondWithJSON(w, http.StatusOK, Response{
        Success: true,
        Data:    empresasIDs,
    })
}

// Handler para buscar un usuario por identificador
func (h *AuthHandler) FindUserByIdentifier(w http.ResponseWriter, r *http.Request) {
    // Obtener token del encabezado
    token := extractToken(r)
    if token == "" {
        respondWithError(w, http.StatusUnauthorized, "No autorizado")
        return
    }

    // Verificar token
    claims, err := h.authService.VerifyToken(r.Context(), token)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, err.Error())
        return
    }

		

    // Obtener el identificador de la query
    identifier := r.URL.Query().Get("identifier")
    if identifier == "" {
        respondWithError(w, http.StatusBadRequest, "Identificador requerido (DNI, email o teléfono)")
        return
    }

	// Registrar quién está realizando la búsqueda para auditoría
    log.Printf("Usuario %s está buscando por identificador: %s", claims.UserID, identifier)

    // Buscar usuario
    user, err := h.authService.FindUserByIdentifier(r.Context(), identifier)
    if err != nil {
        // En lugar de mostrar error, devolver que no se encontró
        respondWithJSON(w, http.StatusOK, Response{
            Success: true,
            Data:    nil,
            Message: "Usuario no encontrado",
        })
        return
    }

    // Ocultar información sensible
    user.Password = ""
    
    // Minimizar la información que se devuelve (solo lo necesario)
    userData := map[string]interface{}{
        "id":        user.ID,
        "dni":       user.DNI,
        "firstName": user.FirstName,
        "lastName":  user.LastName,
        "email":     user.Email,
        "phone":     user.Phone,
        // No incluir información sobre a qué empresas pertenece
    }

    // Responder con el usuario
    respondWithJSON(w, http.StatusOK, Response{
        Success: true,
        Data:    userData,
    })
}

// Handler para añadir un usuario como cliente a una empresa
func (h *AuthHandler) AddClientToEmpresa(w http.ResponseWriter, r *http.Request) {
    // Obtener token del encabezado
    token := extractToken(r)
    if token == "" {
        respondWithError(w, http.StatusUnauthorized, "No autorizado")
        return
    }

    // Verificar token
    claims, err := h.authService.VerifyToken(r.Context(), token)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, err.Error())
        return
    }

	log.Printf("Token verificado correctamente para usuario: %s", claims.UserID)

    // Obtener variables de la URL
    vars := mux.Vars(r)
    userID, err := uuid.Parse(vars["id"])
    if err != nil {
		log.Printf("Error parseando ID de usuario: %v", err)
        respondWithError(w, http.StatusBadRequest, "ID de usuario inválido")
        return
    }
    empresaID, err := uuid.Parse(vars["empresaId"])
    if err != nil {
		log.Printf("Error parseando ID de empresa: %v", err)
        respondWithError(w, http.StatusBadRequest, "ID de empresa inválido")
        return
    }

    // Verificar que el usuario solicitante tiene permisos para esta empresa
    currentUserID, err := uuid.Parse(claims.UserID)
    if err != nil {
		log.Printf("Error parseando ID de usuario del token: %v", err)
        respondWithError(w, http.StatusInternalServerError, "Error en el token")
        return
    }

	log.Printf("Verificando permisos para usuario %s en empresa %s", currentUserID, empresaID)

    // Verificar si tiene permisos administrativos en la empresa
    //!hasPermission, err := h.authService.HasPermission(r.Context(), currentUserID, empresaID, "ADMIN_USERS")
	//!crear el administrador de usuarios de la empresa (supervisor empresa)
   // Verificar si es administrador de la empresa
   hasPermission := false
   isEmpresaAdmin, err := h.authService.HasPermission(r.Context(), currentUserID, empresaID, "EMPRESA_ADMIN")
   if err != nil {
	   log.Printf("Error verificando permiso EMPRESA_ADMIN: %v", err)
   } else if isEmpresaAdmin {
	   hasPermission = true
	   log.Printf("Usuario tiene permiso EMPRESA_ADMIN")
   }
   
   // Si no es admin de empresa, verificar si tiene permiso específico para administrar usuarios
   if !hasPermission {
	   isAdminUsers, err := h.authService.HasPermission(r.Context(), currentUserID, empresaID, "ADMIN_USERS")
	   if err != nil {
		   log.Printf("Error verificando permiso ADMIN_USERS: %v", err)
	   } else if isAdminUsers {
		   hasPermission = true
		   log.Printf("Usuario tiene permiso ADMIN_USERS")
	   }
   }

   if !hasPermission {
	log.Printf("Usuario no tiene permisos para añadir clientes a esta empresa")
	respondWithError(w, http.StatusForbidden, "No tienes permiso para añadir clientes a esta empresa")
	return
}


    // Añadir cliente a la empresa
	log.Printf("Añadiendo cliente %s a empresa %s", userID, empresaID)
    if err := h.authService.AddClientToEmpresa(r.Context(), userID, empresaID); err != nil {
		log.Printf("Error añadiendo cliente: %v", err)
        respondWithError(w, http.StatusInternalServerError, err.Error())
        return
    }

    // Responder con éxito
	log.Printf("Cliente añadido exitosamente")
    respondWithJSON(w, http.StatusOK, Response{
        Success: true,
        Message: "Usuario añadido como cliente a la empresa",
    })
}
//! Handler para obtener usuarios de una empresa
func (h *AuthHandler) GetUsersByEmpresa(w http.ResponseWriter, r *http.Request) {
    // Obtener token del encabezado
    token := extractToken(r)
    if token == "" {
        respondWithPaginatedError(w, http.StatusUnauthorized, "Token de autorización requerido")
        return
    }

    // Verificar token
    claims, err := h.authService.VerifyToken(r.Context(), token)
    if err != nil {
        respondWithPaginatedError(w, http.StatusUnauthorized, "Token inválido o expirado")
        return
    }

    // Obtener y validar ID de la empresa
    vars := mux.Vars(r)
    empresaIDStr := vars["empresaId"]
    
    if errDetail := validateUUID(empresaIDStr, "empresaId"); errDetail != nil {
        respondWithValidationError(w, []ErrorDetail{*errDetail})
        return
    }
    
    empresaID := uuid.MustParse(empresaIDStr)

    // Validar parámetros de paginación
    page, limit, validationErrors := validatePaginationParams(
        r.URL.Query().Get("page"),
        r.URL.Query().Get("limit"),
    )

    if len(validationErrors) > 0 {
        respondWithValidationError(w, validationErrors)
        return
    }

    // Obtener filtro de rol y validarlo
    roleFilter := r.URL.Query().Get("role")
    if roleFilter != "" {
        // Validar que el rol existe
        validRoles := []string{"EMPRESA_ADMIN", "SUPER_ADMIN", "CLIENTE", "EMPLOYEE", "VIEWER"}
        isValidRole := false
        for _, validRole := range validRoles {
            if roleFilter == validRole {
                isValidRole = true
                break
            }
        }
        
        if !isValidRole {
            errors := []ErrorDetail{{
                Code:    "INVALID_ROLE",
                Message: "El rol especificado no es válido",
                Field:   "role",
                Meta: map[string]interface{}{
                    "validRoles": validRoles,
                },
            }}
            respondWithValidationError(w, errors)
            return
        }
    }

    // Verificar permisos del usuario actual
    currentUserID := uuid.MustParse(claims.UserID)
    
    // Primero verificar si es SUPER_ADMIN del sistema
    isSuperAdmin, err := h.authService.HasSystemRole(r.Context(), currentUserID, "SUPER_ADMIN")
    if err != nil {
        log.Printf("Error verificando rol de sistema: %v", err)
        respondWithPaginatedError(w, http.StatusInternalServerError, "Error al verificar permisos del sistema")
        return
    }
    
    if isSuperAdmin {
        log.Printf("Usuario %s es SUPER_ADMIN del sistema", currentUserID)
        // SUPER_ADMIN puede ver todo, continuar con el proceso
    } else {
        // Si no es SUPER_ADMIN, verificar permisos específicos en la empresa
        hasPermission, err := h.authService.HasPermission(r.Context(), currentUserID, empresaID, "ADMIN_USERS")
        if err != nil {
            respondWithPaginatedError(w, http.StatusInternalServerError, "Error al verificar permisos")
            return
        }
        
        if !hasPermission {
            // También verificar si es EMPRESA_ADMIN
            hasEmpresaAdmin, err := h.authService.HasPermission(r.Context(), currentUserID, empresaID, "EMPRESA_ADMIN")
            if err != nil {
                respondWithPaginatedError(w, http.StatusInternalServerError, "Error al verificar permisos de empresa")
                return
            }
            
            if !hasEmpresaAdmin {
                respondWithPaginatedError(w, http.StatusForbidden, "No tienes permisos para ver usuarios de esta empresa")
                return
            }
        }
    }

    // Obtener usuarios de la empresa
    users, total, err := h.authService.GetUsersByEmpresa(r.Context(), empresaID, page, limit, roleFilter)
    if err != nil {
        // Manejar errores específicos del servicio
        switch err.Error() {
        case "empresa no encontrada":
            respondWithPaginatedError(w, http.StatusNotFound, "Empresa no encontrada")
        case "rol no válido":
            errors := []ErrorDetail{{
                Code:    "INVALID_ROLE",
                Message: "Rol de filtro no válido",
                Field:   "role",
            }}
            respondWithValidationError(w, errors)
        case "sin permisos":
            respondWithPaginatedError(w, http.StatusForbidden, "Sin permisos para acceder a esta información")
        default:
            log.Printf("Error obteniendo usuarios de empresa: %v", err)
            respondWithPaginatedError(w, http.StatusInternalServerError, "Error al obtener usuarios")
        }
        return
    }

    // Calcular información de paginación
    totalPages := (total + limit - 1) / limit
    
    // Responder con los usuarios usando PaginatedResponse
    response := PaginatedResponse{
        Success: true,
        Message: "Usuarios obtenidos exitosamente",
        Data:    users,
        Pagination: map[string]interface{}{
            "page":        page,
            "limit":       limit,
            "total":       total,
            "totalPages":  totalPages,
            "hasNext":     page < totalPages,
            "hasPrev":     page > 1,
            "from":        (page-1)*limit + 1,
            "to":          min(page*limit, total),
        },
    }
    
    respondWithPaginatedJSON(w, http.StatusOK, response)
}

// Función helper para obtener el mínimo de dos enteros
func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

//!metodo para listar todos los usuarios con el rol SUPER_ADMIN
func (h *AuthHandler) ListAllUsers(w http.ResponseWriter, r *http.Request) {
    // Verificar token
    token := extractToken(r)
    if token == "" {
        respondWithPaginatedError(w, http.StatusUnauthorized, "Token de autorización requerido")
        return
    }

    claims, err := h.authService.VerifyToken(r.Context(), token)
    if err != nil {
        respondWithPaginatedError(w, http.StatusUnauthorized, "Token inválido o expirado")
        return
    }

    // Obtener ID del usuario del token
    currentUserID, err := uuid.Parse(claims.UserID)
    if err != nil {
        respondWithPaginatedError(w, http.StatusInternalServerError, "Error en el token")
        return
    }

    // Verificar si es SUPER_ADMIN
    isSuperAdmin, err := h.authService.HasSystemRole(r.Context(), currentUserID, "SUPER_ADMIN")
    if err != nil {
        log.Printf("Error verificando rol SUPER_ADMIN: %v", err)
        respondWithPaginatedError(w, http.StatusInternalServerError, "Error verificando permisos")
        return
    }

    if !isSuperAdmin {
        respondWithPaginatedError(w, http.StatusForbidden, "Acceso denegado. Se requiere rol SUPER_ADMIN")
        return
    }

    // Validar parámetros de paginación
    pageStr := r.URL.Query().Get("page")
    limitStr := r.URL.Query().Get("limit")
    page, limit, validationErrors := validatePaginationParams(pageStr, limitStr)

    if len(validationErrors) > 0 {
        respondWithValidationError(w, validationErrors)
        return
    }

    // Obtener filtros adicionales
    filters := make(map[string]string)
    
    // Filtro por estado
    if status := r.URL.Query().Get("status"); status != "" {
        validStatuses := []string{string(entities.UserStatusActive), string(entities.UserStatusInactive), string(entities.UserStatusBlocked)}
        isValid := false
        for _, validStatus := range validStatuses {
            if status == validStatus {
                isValid = true
                break
            }
        }
        
        if !isValid {
            errors := []ErrorDetail{{
                Code:    "INVALID_STATUS",
                Message: "El estado especificado no es válido",
                Field:   "status",
                Meta: map[string]interface{}{
                    "validStatuses": validStatuses,
                },
            }}
            respondWithValidationError(w, errors)
            return
        }
        
        filters["status"] = status
    }
    
    // Filtro por texto de búsqueda (nombre, apellido, email, dni)
    if searchTerm := r.URL.Query().Get("search"); searchTerm != "" {
        filters["search"] = searchTerm
    }

    // Obtener todos los usuarios con paginación
    users, total, err := h.authService.ListAllUsers(r.Context(), page, limit, filters)
    if err != nil {
        log.Printf("Error obteniendo usuarios: %v", err)
        respondWithPaginatedError(w, http.StatusInternalServerError, "Error al obtener usuarios")
        return
    }

    // Calcular información de paginación
    totalPages := (total + limit - 1) / limit
    
    // Responder con los usuarios
    response := PaginatedResponse{
        Success: true,
        Message: "Usuarios obtenidos exitosamente",
        Data:    users,
        Pagination: map[string]interface{}{
            "page":       page,
            "limit":      limit,
            "total":      total,
            "totalPages": totalPages,
            "hasNext":    page < totalPages,
            "hasPrev":    page > 1,
            "from":       (page-1)*limit + 1,
            "to":         min(page*limit, total),
        },
    }
    
    respondWithPaginatedJSON(w, http.StatusOK, response)
}



// Funciones auxiliares

// extractToken extrae el token de autorización del encabezado
func extractToken(r *http.Request) string {
	bearerToken := r.Header.Get("Authorization")
	if len(bearerToken) > 7 && bearerToken[:7] == "Bearer " {
		return bearerToken[7:]
	}
	return ""
}

// respondWithJSON responde con un JSON
func respondWithJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

// respondWithError responde con un error
func respondWithError(w http.ResponseWriter, status int, message string) {
	respondWithJSON(w, status, Response{
		Success: false,
		Error:   message,
	})
}

// ListAllUsersInEmpresa lista todos los usuarios de una empresa específica (sin restricciones para SUPER_ADMIN)
func (h *AuthHandler) ListAllUsersInEmpresa(w http.ResponseWriter, r *http.Request) {
    // Verificar token
    token := extractToken(r)
    if token == "" {
        respondWithPaginatedError(w, http.StatusUnauthorized, "Token de autorización requerido")
        return
    }

    claims, err := h.authService.VerifyToken(r.Context(), token)
    if err != nil {
        respondWithPaginatedError(w, http.StatusUnauthorized, "Token inválido o expirado")
        return
    }

    // Obtener ID del usuario del token
    currentUserID, err := uuid.Parse(claims.UserID)
    if err != nil {
        respondWithPaginatedError(w, http.StatusInternalServerError, "Error en el token")
        return
    }

    // Obtener y validar ID de la empresa
    vars := mux.Vars(r)
    empresaIDStr := vars["empresaId"]
    
    if errDetail := validateUUID(empresaIDStr, "empresaId"); errDetail != nil {
        respondWithValidationError(w, []ErrorDetail{*errDetail})
        return
    }
    
    empresaID := uuid.MustParse(empresaIDStr)

    // Verificar si es SUPER_ADMIN
    isSuperAdmin, err := h.authService.HasSystemRole(r.Context(), currentUserID, "SUPER_ADMIN")
    if err != nil {
        log.Printf("Error verificando rol SUPER_ADMIN: %v", err)
        respondWithPaginatedError(w, http.StatusInternalServerError, "Error verificando permisos")
        return
    }

    // Si no es SUPER_ADMIN, verificar si tiene permisos en la empresa
    if !isSuperAdmin {
        // Verificar si es admin de la empresa
        isEmpresaAdmin, err := h.authService.HasPermission(r.Context(), currentUserID, empresaID, "EMPRESA_ADMIN")
        if err != nil || !isEmpresaAdmin {
            // Verificar si tiene permiso para ver usuarios
            hasViewPermission, err := h.authService.HasPermission(r.Context(), currentUserID, empresaID, "VIEW_USERS")
            if err != nil || !hasViewPermission {
                respondWithPaginatedError(w, http.StatusForbidden, "No tienes permisos para ver usuarios de esta empresa")
                return
            }
        }
    }

    // Validar parámetros de paginación
    pageStr := r.URL.Query().Get("page")
    limitStr := r.URL.Query().Get("limit")
    page, limit, validationErrors := validatePaginationParams(pageStr, limitStr)

    if len(validationErrors) > 0 {
        respondWithValidationError(w, validationErrors)
        return
    }

    // Obtener filtros adicionales
    filters := make(map[string]string)
    
    // Filtro por rol
    if role := r.URL.Query().Get("role"); role != "" {
        filters["role"] = role
    }
    
    // Filtro por estado
    if status := r.URL.Query().Get("status"); status != "" {
        validStatuses := []string{"ACTIVE", "INACTIVE", "BLOCKED"}
        isValid := false
        for _, validStatus := range validStatuses {
            if status == validStatus {
                isValid = true
                break
            }
        }
        
        if !isValid {
            errors := []ErrorDetail{{
                Code:    "INVALID_STATUS",
                Message: "El estado especificado no es válido",
                Field:   "status",
                Meta: map[string]interface{}{
                    "validStatuses": validStatuses,
                },
            }}
            respondWithValidationError(w, errors)
            return
        }
        
        filters["status"] = status
    }
    
    // Filtro por texto de búsqueda (nombre, apellido, email, dni)
    if searchTerm := r.URL.Query().Get("search"); searchTerm != "" {
        filters["search"] = searchTerm
    }

    // Obtener usuarios de la empresa
    users, total, err := h.authService.ListUsersInEmpresa(r.Context(), empresaID, page, limit, filters)
    if err != nil {
        log.Printf("Error obteniendo usuarios: %v", err)
        respondWithPaginatedError(w, http.StatusInternalServerError, "Error al obtener usuarios")
        return
    }

    // Calcular información de paginación
    totalPages := (total + limit - 1) / limit
    
    // Responder con los usuarios
    response := PaginatedResponse{
        Success: true,
        Message: "Usuarios obtenidos exitosamente",
        Data:    users,
        Pagination: map[string]interface{}{
            "page":       page,
            "limit":      limit,
            "total":      total,
            "totalPages": totalPages,
            "hasNext":    page < totalPages,
            "hasPrev":    page > 1,
            "from":       (page-1)*limit + 1,
            "to":         min(page*limit, total),
        },
    }
    
    respondWithPaginatedJSON(w, http.StatusOK, response)
}
