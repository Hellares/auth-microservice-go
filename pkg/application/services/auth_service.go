package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"auth-microservice/pkg/application/ports"
	"auth-microservice/pkg/domain/entities"
	"auth-microservice/pkg/domain/repositories"
	"auth-microservice/pkg/infrastructure/auth"
)

// AuthService define la interfaz del servicio de autenticación
type AuthService interface {
	Register(ctx context.Context, dni, email, password, firstName, lastName, phone string) (*entities.User, error)
	Login(ctx context.Context, dni, password string) (string, error)
	VerifyToken(ctx context.Context, token string) (*auth.TokenClaims, error)
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
	GetUserByDNI(ctx context.Context, dni string) (*entities.User, error)
	GetUserByEmail(ctx context.Context, email string) (*entities.User, error)
	GetRoleByName(ctx context.Context, name string) (*entities.Role, error)

	GetUserEmpresas(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error)

	FindUserByIdentifier(ctx context.Context, identifier string) (*entities.User, error)
	AddClientToEmpresa(ctx context.Context, userID, empresaID uuid.UUID) error
	GetPermissionsByRole(ctx context.Context, roleID uuid.UUID) ([]*entities.Permission, error)
	HasSystemRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error)
	GetUsersByEmpresa(ctx context.Context, empresaID uuid.UUID, page, limit int, roleFilter string) ([]*UserWithRoles, int, error)
	// GetAllUserRoles(ctx context.Context, userID uuid.UUID) ([]*entities.Role, error)
	ListAllUsers(ctx context.Context, page, limit int, filters map[string]string) ([]*UserInfo, int, error)
	ListUsersInEmpresa(ctx context.Context, empresaID uuid.UUID, page, limit int, filters map[string]string) ([]*UserInfo, int, error)

	
}

// authServiceImpl implementa la interfaz AuthService
type authServiceImpl struct {
	userRepo              repositories.UserRepository
	roleRepo              repositories.RoleRepository
	permissionRepo        repositories.PermissionRepository
	userEmpresaRoleRepo   repositories.UserEmpresaRoleRepository
	verificationTokenRepo repositories.VerificationTokenRepository
	sessionRepo           repositories.SessionRepository
	systemRoleRepo 		  repositories.SystemRoleRepository
	jwtService            *auth.JWTService // Reemplaza jwtSecret
	tokenExpiration       time.Duration
	emailSender           ports.EmailSender
}

// Estructura simplificada para roles
type RoleSimple struct {
    ID          uuid.UUID `json:"id"`
    Name        string    `json:"name"`
    Description string    `json:"description,omitempty"`
}

type UserWithRoles struct {
    ID        uuid.UUID    `json:"id"`
    DNI       string       `json:"dni"`
    Email     string       `json:"email"`
    FirstName string       `json:"firstName"`
    LastName  string       `json:"lastName"`
    Phone     string       `json:"phone,omitempty"`
    Status    entities.UserStatus `json:"status"`
    Verified  bool         `json:"verified"`
    CreatedAt time.Time    `json:"createdAt"`
    UpdatedAt time.Time    `json:"updatedAt"`
    //Roles     []*entities.Role `json:"roles"`
	Roles     []RoleSimple        `json:"roles"`
}

type UserInfo struct {
    ID        uuid.UUID            `json:"id"`
    DNI       string               `json:"dni"`
    Email     string               `json:"email"`
    FirstName string               `json:"firstName"`
    LastName  string               `json:"lastName"`
    Phone     string               `json:"phone,omitempty"`
    Status    entities.UserStatus  `json:"status"`
    Verified  bool                 `json:"verified"`
    CreatedAt time.Time            `json:"createdAt"`
    UpdatedAt time.Time            `json:"updatedAt"`
    Empresas  []EmpresaInfo        `json:"empresas,omitempty"`
	Roles     []RoleSimple         `json:"roles,omitempty"` 
}

type EmpresaInfo struct {
    ID   uuid.UUID `json:"id"`
    Role string    `json:"role"`
}

// NewAuthService crea una nueva instancia del servicio de autenticación
func NewAuthService(
	userRepo repositories.UserRepository,
	roleRepo repositories.RoleRepository,
	permissionRepo repositories.PermissionRepository,
	userEmpresaRoleRepo repositories.UserEmpresaRoleRepository,
	verificationTokenRepo repositories.VerificationTokenRepository,
	sessionRepo repositories.SessionRepository,
	systemRoleRepo repositories.SystemRoleRepository,
	jwtSecret string,
	tokenExpiration time.Duration,
	emailSender ports.EmailSender,
	
) AuthService {
	jwtService := auth.NewJWTService(jwtSecret, tokenExpiration)

	return &authServiceImpl{
		userRepo:              userRepo,
		roleRepo:              roleRepo,
		permissionRepo:        permissionRepo,
		userEmpresaRoleRepo:   userEmpresaRoleRepo,
		verificationTokenRepo: verificationTokenRepo,
		sessionRepo:           sessionRepo,
		systemRoleRepo: 	   systemRoleRepo,
		jwtService:            jwtService,
		tokenExpiration:       tokenExpiration,
		emailSender:           emailSender,
		

	}
}

// Register registra un nuevo usuario
func (s *authServiceImpl) Register(ctx context.Context, dni, email, password, firstName, lastName, phone string) (*entities.User, error) {
	// Verificar si el DNI ya está registrado
	existingUser, err := s.userRepo.FindByDNI(ctx, dni)
	if err == nil && existingUser != nil {
		return nil, errors.New("el DNI ya está registrado")
	}

	// Verificar si el email ya está registrado
	existingUser, err = s.userRepo.FindByEmail(ctx, email)
	if err == nil && existingUser != nil {
		return nil, errors.New("el email ya está registrado")
	}

	// Verificar si el teléfono ya está registrado
	existingUser, err = s.userRepo.FindByPhone(ctx, phone)
	if err == nil && existingUser != nil {
		return nil, errors.New("el número de teléfono ya está registrado")
	}

	// Hash de la contraseña
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := &entities.User{
		ID:        uuid.New(),
		DNI:       dni,
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
	verificationToken, err := s.CreateVerificationToken(ctx, user.ID, entities.TokenTypeEmailVerification)
	if err != nil {
		return nil, err
	}

	// Enviar email de verificación
	if err := s.emailSender.SendVerificationEmail(user, verificationToken.Token); err != nil {
		return nil, err
	}

	return user, nil
}

// Login autentica a un usuario
func (s *authServiceImpl) Login(ctx context.Context, dni, password string) (string, error) {
	// Buscar usuario por DNI
	user, err := s.userRepo.FindByDNI(ctx, dni)
	if err != nil {
		return "", errors.New("credenciales inválidas")
	}

	// Verificar contraseña
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return "", errors.New("credenciales inválidas")
	}

	// Crear claims para el token JWT
	claims := &auth.TokenClaims{
		UserID: user.ID.String(),
		DNI:    user.DNI,
		Email:  user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.tokenExpiration)),
		},
	}

	// Generar token JWT
	token, err := s.jwtService.GenerateToken(claims)
	if err != nil {
		return "", fmt.Errorf("error al generar el token: %v", err)
	}

	// Crear sesión
	session := &entities.Session{
		ID:        uuid.New(),
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(s.tokenExpiration),
		CreatedAt: time.Now(),
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return "", fmt.Errorf("error al crear la sesión: %v", err)
	}

	return token, nil
}

// VerifyToken verifica un token JWT y devuelve los claims
func (s *authServiceImpl) VerifyToken(ctx context.Context, tokenString string) (*auth.TokenClaims, error) {
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

	return claims, nil
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
	token, err := s.CreateVerificationToken(ctx, user.ID, entities.TokenTypePasswordReset)
	if err != nil {
		return nil, err
	}

	// Enviar email con el token
	if err := s.emailSender.SendPasswordResetEmail(user, token.Token); err != nil {
		return nil, err
	}

	return token, nil
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
	// Primero, verificar si es un rol de sistema
    if permissionName == "SUPER_ADMIN" || permissionName == "SYSTEM_ADMIN" {
        return s.HasSystemRole(ctx, userID, permissionName)
    }
	// Para permisos de empresa, continuar con la lógica existente
    if empresaID == uuid.Nil {
        // Si no hay empresa especificada y no es un rol de sistema, no tiene permiso
        return false, nil
    }

	// Log para debugging
	log.Printf("Verificando permiso %s para usuario %s en empresa %s", permissionName, userID, empresaID)
	// Obtener los roles del usuario en la empresa
	roles, err := s.GetUserRoles(ctx, userID, empresaID)
	if err != nil {
		log.Printf("Error obteniendo roles: %v", err)
		return false, err
	}

	log.Printf("Usuario tiene %d roles en la empresa", len(roles))
	// Para cada rol, verificar si tiene el permiso
	for _, role := range roles {
		log.Printf("Verificando rol: %s", role.Name)

		// Si estamos buscando un permiso que es igual al nombre del rol
        if role.Name == permissionName {
            log.Printf("Usuario tiene el rol %s", permissionName)
            return true, nil
        }
		
		
		// Obtener permisos del rol
        permissions, err := s.permissionRepo.FindByRole(ctx, role.ID)
        if err != nil {
            log.Printf("Error obteniendo permisos del rol %s: %v", role.Name, err)
            continue
        }

		for _, permission := range permissions {
			if permission.Name == permissionName {
				log.Printf("Usuario tiene el permiso %s a través del rol %s", permissionName, role.Name)
				return true, nil
			}
		}
	}

	log.Printf("Usuario no tiene el permiso %s", permissionName)
	return false, nil
}

// GetUserByDNI obtiene un usuario por su DNI
func (s *authServiceImpl) GetUserByDNI(ctx context.Context, dni string) (*entities.User, error) {
	return s.userRepo.FindByDNI(ctx, dni)
}

// GetUserByEmail obtiene un usuario por su email
func (s *authServiceImpl) GetUserByEmail(ctx context.Context, email string) (*entities.User, error) {
	return s.userRepo.FindByEmail(ctx, email)
}

// GetRoleByName obtiene un rol por su nombre
func (s *authServiceImpl) GetRoleByName(ctx context.Context, name string) (*entities.Role, error) {
	return s.roleRepo.FindByName(ctx, name)
}


// GetUserEmpresas obtiene las empresas asociadas a un usuario
// y devuelve una lista de IDs de empresas
func (s *authServiceImpl) GetUserEmpresas(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	
	// Verificar que el usuario existe
	_, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, errors.New("usuario no encontrado")
	}

	// Obtener las empresas asociadas al usuario
	return s.userEmpresaRoleRepo.FindEmpresasByUserID(ctx, userID)
}


func (s *authServiceImpl) FindUserByIdentifier(ctx context.Context, identifier string) (*entities.User, error) {
    //! Buscar por identificador único (DNI, email o teléfono)
    return s.userRepo.FindByIdentifier(ctx, identifier)
}

func (s *authServiceImpl) AddClientToEmpresa(ctx context.Context, userID, empresaID uuid.UUID) error {
    // Buscar rol de cliente
    clienteRole, err := s.roleRepo.FindByName(ctx, "CLIENTE")
    if err != nil {
        return errors.New("rol de cliente no encontrado")
    }

    // Verificar si ya existe esta relación
    existingRoles, err := s.userEmpresaRoleRepo.FindByUserAndEmpresa(ctx, userID, empresaID)
    if err == nil && len(existingRoles) > 0 {
        for _, existing := range existingRoles {
            if existing.RoleID == clienteRole.ID {
                // Si ya existe pero está inactivo, activarlo
                if !existing.Active {
                    existing.Active = true
                    existing.UpdatedAt = time.Now()
                    return s.userEmpresaRoleRepo.Update(ctx, existing)
                }
                return errors.New("el usuario ya es cliente de esta empresa")
            }
        }
    }

    // Crear nueva relación
    userEmpresaRole := &entities.UserEmpresaRole{
        ID:        uuid.New(),
        UserID:    userID,
        EmpresaID: empresaID,
        RoleID:    clienteRole.ID,
        Active:    true,
        CreatedAt: time.Now(),
        UpdatedAt: time.Now(),
    }

    return s.userEmpresaRoleRepo.Create(ctx, userEmpresaRole)
}

func (s *authServiceImpl) GetPermissionsByRole(ctx context.Context, roleID uuid.UUID) ([]*entities.Permission, error) {
    return s.permissionRepo.FindByRole(ctx, roleID)
}

func (s *authServiceImpl) HasSystemRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error) {
    return s.systemRoleRepo.HasSystemRole(ctx, userID, roleName)
}



func (s *authServiceImpl) GetUsersByEmpresa(ctx context.Context, empresaID uuid.UUID, page, limit int, roleFilter string) ([]*UserWithRoles, int, error) {
    // Primero, obtenemos los IDs de usuarios que pertenecen a esta empresa
    userIDs, err := s.userEmpresaRoleRepo.GetUsersByEmpresa(ctx, empresaID, roleFilter)
    if err != nil {
        return nil, 0, err
    }
    
    if len(userIDs) == 0 {
        return []*UserWithRoles{}, 0, nil
    }
    
    // Obtenemos la información completa de los usuarios
    users, total, err := s.userRepo.FindByIDs(ctx, userIDs, page, limit)
    if err != nil {
        return nil, 0, err
    }
    
    // Convertir a UserWithRoles e incluir los roles
	usersWithRoles := make([]*UserWithRoles, len(users))
    for i, user := range users {
        roles, err := s.GetUserRoles(ctx, user.ID, empresaID)
        if err != nil {
            log.Printf("Error obteniendo roles para usuario %s: %v", user.ID, err)
            roles = []*entities.Role{}
        }

		// Convertir roles a RoleSimple
        simpleRoles := make([]RoleSimple, len(roles))
        for j, role := range roles {
            simpleRoles[j] = RoleSimple{
                ID:          role.ID,
                Name:        role.Name,
                Description: role.Description,
            }
        }
        
        usersWithRoles[i] = &UserWithRoles{
            ID:        user.ID,
            DNI:       user.DNI,
            Email:     user.Email,
            FirstName: user.FirstName,
            LastName:  user.LastName,
            Phone:     user.Phone,
            Status:    user.Status,
            Verified:  user.Verified,
            CreatedAt: user.CreatedAt,
            UpdatedAt: user.UpdatedAt,
            Roles:     simpleRoles,
        }
    }
    
    return usersWithRoles, total, nil
}

// func (s *authServiceImpl) GetAllUserRoles(ctx context.Context, userID uuid.UUID) ([]*entities.Role, error) {
//     var allRoles []*entities.Role
    
//     // 1. Obtener roles del sistema
//     systemRoles, err := s.systemRoleRepo.FindByUserID(ctx, userID)
//     if err != nil {
//         log.Printf("Error obteniendo roles del sistema: %v", err)
//     } else {
//         // Convertir system roles a entities.Role
//         for _, sysRole := range systemRoles {
//             if sysRole.Active {
//                 // Buscar el rol correspondiente en la tabla roles
//                 role, err := s.roleRepo.FindByName(ctx, sysRole.RoleName)
//                 if err == nil && role != nil {
//                     allRoles = append(allRoles, role)
//                 } else {
//                     // Si no existe en la tabla roles, crear uno temporal
//                     allRoles = append(allRoles, &entities.Role{
//                         ID:          uuid.New(),
//                         Name:        sysRole.RoleName,
//                         Description: "Rol del sistema",
//                         CreatedAt:   time.Now(),
//                         UpdatedAt:   time.Now(),
//                     })
//                 }
//             }
//         }
//     }
    
//     // 2. Obtener roles de empresa usando el repositorio
//     empresaRoles, err := s.roleRepo.FindAllByUserID(ctx, userID)
//     if err != nil {
//         log.Printf("Error obteniendo roles de empresa: %v", err)
//     } else {
//         allRoles = append(allRoles, empresaRoles...)
//     }
    
//     return allRoles, nil
// }

func (s *authServiceImpl) ListAllUsers(ctx context.Context, page, limit int, filters map[string]string) ([]*UserInfo, int, error) {
    // Obtener usuarios con paginación y filtros
    users, total, err := s.userRepo.ListWithFilters(ctx, page, limit, filters)
    if err != nil {
        return nil, 0, err
    }
    
    userInfos := make([]*UserInfo, len(users))
    
    for i, user := range users {
        // Para cada usuario, obtener sus empresas y roles
        empresaRoles, err := s.userEmpresaRoleRepo.FindByUserID(ctx, user.ID)
        if err != nil {
            log.Printf("Error obteniendo empresas para usuario %s: %v", user.ID, err)
            empresaRoles = []*entities.UserEmpresaRole{}
        }
        
        // Mapa para agrupar por empresa (para evitar duplicados)
        empresasMap := make(map[uuid.UUID]string)
        
        for _, er := range empresaRoles {
            // Obtener nombre del rol
            role, err := s.roleRepo.FindByID(ctx, er.RoleID)
            if err != nil {
                log.Printf("Error obteniendo rol %s: %v", er.RoleID, err)
                continue
            }
            
            // Si ya existe esta empresa, verificar si el rol actual tiene mayor prioridad
            if existingRole, found := empresasMap[er.EmpresaID]; found {
                if isPriorityRole(role.Name) && !isPriorityRole(existingRole) {
                    empresasMap[er.EmpresaID] = role.Name
                }
            } else {
                empresasMap[er.EmpresaID] = role.Name
            }
        }
        
        // Convertir mapa a slice
        empresas := make([]EmpresaInfo, 0, len(empresasMap))
        for empresaID, roleName := range empresasMap {
            empresas = append(empresas, EmpresaInfo{
                ID:   empresaID,
                Role: roleName,
            })
        }
        
        // Crear UserInfo
        userInfos[i] = &UserInfo{
            ID:        user.ID,
            DNI:       user.DNI,
            Email:     user.Email,
            FirstName: user.FirstName,
            LastName:  user.LastName,
            Phone:     user.Phone,
            Status:    user.Status,
            Verified:  user.Verified,
            CreatedAt: user.CreatedAt,
            UpdatedAt: user.UpdatedAt,
            Empresas:  empresas,
        }
    }
    
    return userInfos, total, nil
}

//! Función auxiliar para determinar si un rol tiene prioridad
func isPriorityRole(roleName string) bool {
    priorityRoles := []string{"EMPRESA_ADMIN", "ADMIN_USERS", "ADMIN"}
    for _, role := range priorityRoles {
        if roleName == role {
            return true
        }
    }
    return false
}

func (s *authServiceImpl) ListUsersInEmpresa(ctx context.Context, empresaID uuid.UUID, page, limit int, filters map[string]string) ([]*UserInfo, int, error) {
    // Obtener todos los IDs de usuarios de esta empresa
    userIDs, err := s.userEmpresaRoleRepo.GetAllUsersByEmpresa(ctx, empresaID, filters["role"])
    if err != nil {
        return nil, 0, err
    }
    
    if len(userIDs) == 0 {
        return []*UserInfo{}, 0, nil
    }
    
    // Crear un nuevo mapa de filtros que incluya los IDs
    userFilters := make(map[string]interface{})
    for k, v := range filters {
        if k != "role" { // El filtro de rol ya se aplicó al obtener los userIDs
            userFilters[k] = v
        }
    }
    userFilters["ids"] = userIDs
    
    // Obtener usuarios con paginación y filtros
    users, total, err := s.userRepo.ListWithAdvancedFilters(ctx, page, limit, userFilters)
    if err != nil {
        return nil, 0, err
    }
    
    userInfos := make([]*UserInfo, len(users))
    
    for i, user := range users {
        // Para cada usuario, obtener sus roles en esta empresa
        roles, err := s.GetUserRoles(ctx, user.ID, empresaID)
        if err != nil {
            log.Printf("Error obteniendo roles para usuario %s: %v", user.ID, err)
            roles = []*entities.Role{}
        }
        
        // Convertir roles a formato simple
        roleInfos := make([]RoleSimple, len(roles))
        for j, role := range roles {
            roleInfos[j] = RoleSimple{
                ID:          role.ID,
                Name:        role.Name,
                Description: role.Description,
            }
        }
        
        // Crear UserInfo (sin incluir todas las empresas para esta vista)
        userInfos[i] = &UserInfo{
            ID:        user.ID,
            DNI:       user.DNI,
            Email:     user.Email,
            FirstName: user.FirstName,
            LastName:  user.LastName,
            Phone:     user.Phone,
            Status:    user.Status,
            Verified:  user.Verified,
            CreatedAt: user.CreatedAt,
            UpdatedAt: user.UpdatedAt,
            Roles:     roleInfos,
        }
    }
    
    return userInfos, total, nil
}
