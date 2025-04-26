package services

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"auth-microservice/pkg/domain/entities"
	"auth-microservice/pkg/domain/repositories"
	"auth-microservice/pkg/infrastructure/auth"
)

// AuthService define la interfaz del servicio de autenticación
type AuthService interface {
	Register(ctx context.Context, email, password, firstName, lastName, phone string) (*entities.User, error)
	Login(ctx context.Context, email, password string) (string, error)
	VerifyToken(ctx context.Context, token string) (*TokenClaims, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*entities.User, error)
	ChangePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error
	RequestPasswordReset(ctx context.Context, email string) (*entities.VerificationToken, error)
	ResetPassword(ctx context.Context, token, newPassword string) error
	CreateVerificationToken(ctx context.Context, userID uuid.UUID, tokenType entities.TokenType) (*entities.VerificationToken, error)
	VerifyEmail(ctx context.Context, token string) error
	CreateEmpresaAdmin(ctx context.Context, user *entities.User, empresaID uuid.UUID) error
	AddUserToEmpresa(ctx context.Context, userID, empresaID uuid.UUID, roleID uuid.UUID) error
	RemoveUserFromEmpresa(ctx context.Context, userID, empresaID uuid.UUID) error
	GetUserRoles(ctx context.Context, userID, empresaID uuid.UUID) ([]*entities.Role, error)
	HasPermission(ctx context.Context, userID, empresaID uuid.UUID, permissionName string) (bool, error)
	GetUserByEmail(ctx context.Context, email string) (*entities.User, error)
	GetRoleByName(ctx context.Context, name string) (*entities.Role, error)
}

// TokenClaims son los datos que se incluyen en el JWT
type TokenClaims struct {
	UserID    string `json:"userId"`
	Email     string `json:"email"`
	ExpiresAt int64  `json:"exp"`
}

// authServiceImpl implementa la interfaz AuthService
type authServiceImpl struct {
	userRepo              repositories.UserRepository
	roleRepo              repositories.RoleRepository
	permissionRepo        repositories.PermissionRepository
	userEmpresaRoleRepo   repositories.UserEmpresaRoleRepository
	verificationTokenRepo repositories.VerificationTokenRepository
	sessionRepo           repositories.SessionRepository
	jwtService            *auth.JWTService  // Reemplaza jwtSecret
	tokenExpiration       time.Duration
}

// NewAuthService crea una nueva instancia del servicio de autenticación
func NewAuthService(
	userRepo repositories.UserRepository,
	roleRepo repositories.RoleRepository,
	permissionRepo repositories.PermissionRepository,
	userEmpresaRoleRepo repositories.UserEmpresaRoleRepository,
	verificationTokenRepo repositories.VerificationTokenRepository,
	sessionRepo repositories.SessionRepository,
	jwtSecret string,
	tokenExpiration time.Duration,
) AuthService {
	jwtService := auth.NewJWTService(jwtSecret, tokenExpiration)

	return &authServiceImpl{
		userRepo:              userRepo,
		roleRepo:              roleRepo,
		permissionRepo:        permissionRepo,
		userEmpresaRoleRepo:   userEmpresaRoleRepo,
		verificationTokenRepo: verificationTokenRepo,
		sessionRepo:           sessionRepo,
		jwtService:            jwtService,
		tokenExpiration:       tokenExpiration,
	}
}

// Register registra un nuevo usuario
func (s *authServiceImpl) Register(ctx context.Context, email, password, firstName, lastName, phone string) (*entities.User, error) {
	// Verificar si el email ya está registrado
	existingUser, err := s.userRepo.FindByEmail(ctx, email)
	if err == nil && existingUser != nil {
		return nil, errors.New("el email ya está registrado")
	}

	// Hash de la contraseña
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := &entities.User{
		ID:        uuid.New(),
		Email:     email,
		Password:  string(hashedPassword),
		FirstName: firstName,
		LastName:  lastName,
		Phone:     phone,
		Status:    entities.UserStatusActive,
		Verified:  false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	// Generar token de verificación de email
	_, err = s.CreateVerificationToken(ctx, user.ID, entities.TokenTypeEmailVerification)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// Login autentica a un usuario y devuelve un token JWT
func (s *authServiceImpl) Login(ctx context.Context, email, password string) (string, error) {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return "", errors.New("credenciales inválidas")
	}

	if user.Status != entities.UserStatusActive {
		return "", errors.New("usuario inactivo o bloqueado")
	}

	// Verificar contraseña
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return "", errors.New("credenciales inválidas")
	}

	// Actualizar último inicio de sesión
	if err := s.userRepo.UpdateLastLogin(ctx, user.ID); err != nil {
		return "", err
	}

	// Generar token JWT usando el servicio
	tokenString, err := s.jwtService.GenerateToken(user.ID, user.Email)
	if err != nil {
		return "", err
	}

	

	// Crear sesión
	session := &entities.Session{
		ID:        uuid.New(),
		UserID:    user.ID,
		Token:     tokenString,
		ExpiresAt: time.Now().Add(s.tokenExpiration),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return "", err
	}

	return tokenString, nil
}

// VerifyToken verifica un token JWT y devuelve los claims
// func (s *authServiceImpl) VerifyToken(ctx context.Context, tokenString string) (*TokenClaims, error) {
// 	// Verificar si el token existe en la base de datos
// 	session, err := s.sessionRepo.FindByToken(ctx, tokenString)
// 	if err != nil || session == nil || time.Now().After(session.ExpiresAt) {
// 		return nil, errors.New("token inválido o expirado")
// 	}

// 	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
// 		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
// 			return nil, errors.New("método de firma inesperado")
// 		}
// 		return s.jwtSecret, nil
// 	})

// 	if err != nil {
// 		return nil, err
// 	}

// 	if !token.Valid {
// 		return nil, errors.New("token inválido")
// 	}

// 	claims, ok := token.Claims.(jwt.MapClaims)
// 	if !ok {
// 		return nil, errors.New("no se pudieron extraer los claims del token")
// 	}

// 	userID, ok := claims["userId"].(string)
// 	if !ok {
// 		return nil, errors.New("no se pudo extraer el ID de usuario del token")
// 	}

// 	email, ok := claims["email"].(string)
// 	if !ok {
// 		return nil, errors.New("no se pudo extraer el email del token")
// 	}

// 	exp, ok := claims["exp"].(float64)
// 	if !ok {
// 		return nil, errors.New("no se pudo extraer la fecha de expiración del token")
// 	}

// 	return &TokenClaims{
// 		UserID:    userID,
// 		Email:     email,
// 		ExpiresAt: int64(exp),
// 	}, nil
// }

// Modificar el método VerifyToken para usar jwtService
func (s *authServiceImpl) VerifyToken(ctx context.Context, tokenString string) (*TokenClaims, error) {
	// Verificar si el token existe en la base de datos
	session, err := s.sessionRepo.FindByToken(ctx, tokenString)
	if err != nil || session == nil || time.Now().After(session.ExpiresAt) {
		return nil, errors.New("token inválido o expirado")
	}

	// Validar token usando el servicio JWT
	claims, err := s.jwtService.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	return &TokenClaims{
		UserID:    claims.UserID,
		Email:     claims.Email,
		ExpiresAt: claims.ExpiresAt.Unix(),
	}, nil
}

// GetUserByID obtiene un usuario por su ID
func (s *authServiceImpl) GetUserByID(ctx context.Context, id uuid.UUID) (*entities.User, error) {
	return s.userRepo.FindByID(ctx, id)
}

// ChangePassword cambia la contraseña de un usuario
func (s *authServiceImpl) ChangePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return err
	}

	// Verificar contraseña actual
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(currentPassword)); err != nil {
		return errors.New("contraseña actual incorrecta")
	}

	// Hash de la nueva contraseña
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return s.userRepo.UpdatePassword(ctx, userID, string(hashedPassword))
}

// RequestPasswordReset solicita un reseteo de contraseña
func (s *authServiceImpl) RequestPasswordReset(ctx context.Context, email string) (*entities.VerificationToken, error) {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, errors.New("usuario no encontrado")
	}

	// Eliminar tokens de reseteo anteriores
	existingToken, err := s.verificationTokenRepo.FindByUserAndType(ctx, user.ID, entities.TokenTypePasswordReset)
	if err == nil && existingToken != nil {
		if err := s.verificationTokenRepo.Delete(ctx, existingToken.ID); err != nil {
			return nil, err
		}
	}

	// Crear nuevo token de reseteo
	return s.CreateVerificationToken(ctx, user.ID, entities.TokenTypePasswordReset)
}

// ResetPassword resetea la contraseña de un usuario usando un token
func (s *authServiceImpl) ResetPassword(ctx context.Context, token, newPassword string) error {
	verificationToken, err := s.verificationTokenRepo.FindByToken(ctx, token)
	if err != nil {
		return errors.New("token inválido")
	}

	if verificationToken.Type != entities.TokenTypePasswordReset {
		return errors.New("tipo de token incorrecto")
	}

	if time.Now().After(verificationToken.ExpiresAt) {
		return errors.New("token expirado")
	}

	// Hash de la nueva contraseña
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Actualizar contraseña
	if err := s.userRepo.UpdatePassword(ctx, verificationToken.UserID, string(hashedPassword)); err != nil {
		return err
	}

	// Eliminar token usado
	return s.verificationTokenRepo.Delete(ctx, verificationToken.ID)
}

// CreateVerificationToken crea un token de verificación para un usuario
func (s *authServiceImpl) CreateVerificationToken(ctx context.Context, userID uuid.UUID, tokenType entities.TokenType) (*entities.VerificationToken, error) {
	// Generar token aleatorio
	tokenUUID := uuid.New()
	token := tokenUUID.String()
	
	// Definir expiración (24 horas para verificación de email, 1 hora para reseteo de contraseña)
	var expiresAt time.Time
	if tokenType == entities.TokenTypeEmailVerification {
		expiresAt = time.Now().Add(24 * time.Hour)
	} else {
		expiresAt = time.Now().Add(1 * time.Hour)
	}
	
	verificationToken := &entities.VerificationToken{
		ID:        uuid.New(),
		UserID:    userID,
		Token:     token,
		Type:      tokenType,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}
	
	if err := s.verificationTokenRepo.Create(ctx, verificationToken); err != nil {
		return nil, err
	}
	
	return verificationToken, nil
}

// VerifyEmail verifica el email de un usuario usando un token
func (s *authServiceImpl) VerifyEmail(ctx context.Context, token string) error {
	verificationToken, err := s.verificationTokenRepo.FindByToken(ctx, token)
	if err != nil {
		return errors.New("token inválido")
	}
	
	if verificationToken.Type != entities.TokenTypeEmailVerification {
		return errors.New("tipo de token incorrecto")
	}
	
	if time.Now().After(verificationToken.ExpiresAt) {
		return errors.New("token expirado")
	}
	
	// Marcar email como verificado
	if err := s.userRepo.VerifyEmail(ctx, verificationToken.UserID); err != nil {
		return err
	}
	
	// Eliminar token usado
	return s.verificationTokenRepo.Delete(ctx, verificationToken.ID)
}

// CreateEmpresaAdmin crea un administrador para una empresa
func (s *authServiceImpl) CreateEmpresaAdmin(ctx context.Context, user *entities.User, empresaID uuid.UUID) error {
	// Buscar el rol de administrador de empresa
	adminRole, err := s.roleRepo.FindByName(ctx, "EMPRESA_ADMIN")
	if err != nil {
		return err
	}
	
	// Asignar rol de administrador al usuario para la empresa
	userEmpresaRole := &entities.UserEmpresaRole{
		ID:        uuid.New(),
		UserID:    user.ID,
		EmpresaID: empresaID,
		RoleID:    adminRole.ID,
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	return s.userEmpresaRoleRepo.Create(ctx, userEmpresaRole)
}

// AddUserToEmpresa añade un usuario a una empresa con un rol específico
func (s *authServiceImpl) AddUserToEmpresa(ctx context.Context, userID, empresaID, roleID uuid.UUID) error {
	// Verificar que el usuario existe
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	
	// Verificar que el rol existe
	role, err := s.roleRepo.FindByID(ctx, roleID)
	if err != nil {
		return err
	}
	
	// Verificar si ya existe esta relación
	existingRoles, err := s.userEmpresaRoleRepo.FindByUserAndEmpresa(ctx, userID, empresaID)
	if err == nil && len(existingRoles) > 0 {
		for _, existing := range existingRoles {
			if existing.RoleID == roleID {
				return errors.New("el usuario ya tiene este rol en la empresa")
			}
		}
	}
	
	// Crear la relación usuario-empresa-rol
	userEmpresaRole := &entities.UserEmpresaRole{
		ID:        uuid.New(),
		UserID:    user.ID,
		EmpresaID: empresaID,
		RoleID:    role.ID,
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	return s.userEmpresaRoleRepo.Create(ctx, userEmpresaRole)
}

// RemoveUserFromEmpresa elimina un usuario de una empresa
func (s *authServiceImpl) RemoveUserFromEmpresa(ctx context.Context, userID, empresaID uuid.UUID) error {
	relationships, err := s.userEmpresaRoleRepo.FindByUserAndEmpresa(ctx, userID, empresaID)
	if err != nil {
		return err
	}
	
	for _, rel := range relationships {
		if err := s.userEmpresaRoleRepo.Delete(ctx, rel.ID); err != nil {
			return err
		}
	}
	
	return nil
}

// GetUserRoles obtiene los roles de un usuario en una empresa
func (s *authServiceImpl) GetUserRoles(ctx context.Context, userID, empresaID uuid.UUID) ([]*entities.Role, error) {
	return s.roleRepo.FindByUserAndEmpresa(ctx, userID, empresaID)
}

// HasPermission verifica si un usuario tiene un permiso específico en una empresa
func (s *authServiceImpl) HasPermission(ctx context.Context, userID, empresaID uuid.UUID, permissionName string) (bool, error) {
	// Obtener los roles del usuario en la empresa
	roles, err := s.GetUserRoles(ctx, userID, empresaID)
	if err != nil {
		return false, err
	}
	
	// Para cada rol, verificar si tiene el permiso
	for _, role := range roles {
		permissions, err := s.permissionRepo.FindByRole(ctx, role.ID)
		if err != nil {
			continue
		}
		
		for _, permission := range permissions {
			if permission.Name == permissionName {
				return true, nil
			}
		}
	}
	
	return false, nil
}

// GetUserByEmail obtiene un usuario por su email
func (s *authServiceImpl) GetUserByEmail(ctx context.Context, email string) (*entities.User, error) {
	return s.userRepo.FindByEmail(ctx, email)
}

// GetRoleByName obtiene un rol por su nombre
func (s *authServiceImpl) GetRoleByName(ctx context.Context, name string) (*entities.Role, error) {
	return s.roleRepo.FindByName(ctx, name)
}