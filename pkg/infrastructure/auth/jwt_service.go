package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

// TokenClaims representa los datos incluidos en el token JWT
type TokenClaims struct {
	UserID    string `json:"userId"`
	DNI       string `json:"dni"`
	Email     string `json:"email"`
	ExpiresAt int64  `json:"exp"`
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
func (s *JWTService) GenerateToken(claims *TokenClaims) (string, error) {
	expirationTime := time.Now().Add(s.expiration)

	claims.RegisteredClaims = jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expirationTime),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.secretKey)

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ValidateToken valida un token JWT y devuelve los claims
func (s *JWTService) ValidateToken(tokenString string) (*TokenClaims, error) {
	claims := &TokenClaims{}

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
	expirationTime := time.Unix(claims.ExpiresAt, 0)
	now := time.Now()

	// Si el token expira en menos de 12 horas, generamos uno nuevo
	if expirationTime.Sub(now) < 12*time.Hour {
		return s.GenerateToken(claims)
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

// GetDNIFromToken extrae el DNI de un token
func (s *JWTService) GetDNIFromToken(tokenString string) (string, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}

	return claims.DNI, nil
}

// GetEmailFromToken extrae el email de un token
func (s *JWTService) GetEmailFromToken(tokenString string) (string, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}

	return claims.Email, nil
}
