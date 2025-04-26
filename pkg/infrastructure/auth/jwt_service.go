package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

// Claims representa los datos incluidos en el token JWT
type Claims struct {
	UserID string `json:"userId"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// JWTService proporciona métodos para trabajar con tokens JWT
type JWTService struct {
	secretKey  []byte
	expiration time.Duration
}

// NewJWTService crea una nueva instancia del servicio JWT
func NewJWTService(secretKey string, expiration time.Duration) *JWTService {
	return &JWTService{
		secretKey:  []byte(secretKey),
		expiration: expiration,
	}
}

// GenerateToken genera un nuevo token JWT para un usuario
func (s *JWTService) GenerateToken(userID uuid.UUID, email string) (string, error) {
	expirationTime := time.Now().Add(s.expiration)
	
	claims := &Claims{
		UserID: userID.String(),
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.secretKey)

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ValidateToken valida un token JWT y devuelve los claims
func (s *JWTService) ValidateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("método de firma inesperado")
		}
		return s.secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("token inválido")
	}

	return claims, nil
}

// RefreshToken genera un nuevo token a partir de uno existente
func (s *JWTService) RefreshToken(tokenString string) (string, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}

	// Comprobar si el token está próximo a expirar
	expirationTime := time.Unix(claims.ExpiresAt.Unix(), 0)
	now := time.Now()
	
	// Si el token expira en menos de 12 horas, generamos uno nuevo
	if expirationTime.Sub(now) < 12*time.Hour {
		userID, err := uuid.Parse(claims.UserID)
		if err != nil {
			return "", err
		}
		
		return s.GenerateToken(userID, claims.Email)
	}
	
	// Si no está próximo a expirar, devolvemos el mismo token
	return tokenString, nil
}

// GetUserIDFromToken extrae el ID de usuario de un token
func (s *JWTService) GetUserIDFromToken(tokenString string) (uuid.UUID, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return uuid.Nil, err
	}
	
	return uuid.Parse(claims.UserID)
}

// GetEmailFromToken extrae el email de un token
func (s *JWTService) GetEmailFromToken(tokenString string) (string, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}
	
	return claims.Email, nil
}