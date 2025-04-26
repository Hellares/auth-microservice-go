package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"auth-microservice/pkg/application/services"
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

// NewAuthHandler crea un nuevo handler de autenticación
func NewAuthHandler(authService services.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

// RegisterRoutes registra las rutas para el handler
func (h *AuthHandler) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/register", h.Register).Methods("POST")
	router.HandleFunc("/login", h.Login).Methods("POST")
	router.HandleFunc("/verify-email", h.VerifyEmail).Methods("POST")
	router.HandleFunc("/request-password-reset", h.RequestPasswordReset).Methods("POST")
	router.HandleFunc("/reset-password", h.ResetPassword).Methods("POST")
	router.HandleFunc("/change-password", h.ChangePassword).Methods("POST")
	router.HandleFunc("/me", h.GetCurrentUser).Methods("GET")
	router.HandleFunc("/users/{id}", h.GetUser).Methods("GET")
	router.HandleFunc("/users/{id}/roles", h.GetUserRoles).Methods("GET")
	router.HandleFunc("/users/{id}/permissions", h.GetUserPermissions).Methods("GET")
}

// Register maneja el registro de nuevos usuarios
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	// Estructura para la petición
	var req struct {
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
	if req.Email == "" || req.Password == "" || req.FirstName == "" || req.LastName == "" {
		respondWithError(w, http.StatusBadRequest, "Campos requeridos faltantes")
		return
	}

	// Registrar usuario
	user, err := h.authService.Register(r.Context(), req.Email, req.Password, req.FirstName, req.LastName, req.Phone)
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
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	// Decodificar JSON
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Petición inválida")
		return
	}

	// Validar datos
	if req.Email == "" || req.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Email y contraseña son requeridos")
		return
	}

	// Iniciar sesión
	token, err := h.authService.Login(r.Context(), req.Email, req.Password)
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
	// Estructura para la petición
	var req struct {
		Token string `json:"token"`
	}

	// Decodificar JSON
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Petición inválida")
		return
	}

	// Validar datos
	if req.Token == "" {
		respondWithError(w, http.StatusBadRequest, "Token requerido")
		return
	}

	// Verificar email
	err = h.authService.VerifyEmail(r.Context(), req.Token)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Responder con éxito
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