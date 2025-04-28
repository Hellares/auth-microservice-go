package entities

import (
	"time"

	"github.com/google/uuid"
)

type UserStatus string

const (
	UserStatusActive   UserStatus = "ACTIVE"
	UserStatusInactive UserStatus = "INACTIVE"
	UserStatusBlocked  UserStatus = "BLOCKED"
)

type User struct {
	ID        uuid.UUID  `json:"id"`
	DNI       string     `json:"dni"`
	Email     string     `json:"email"`
	Password  string     `json:"-"` // No enviamos la contraseña en respuestas JSON
	FirstName string     `json:"firstName"`
	LastName  string     `json:"lastName"`
	Phone     string     `json:"phone,omitempty"`
	AvatarURL string     `json:"avatarUrl,omitempty"`
	Status    UserStatus `json:"status"`
	Verified  bool       `json:"verified"`
	LastLogin *time.Time `json:"lastLogin,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
	UpdatedAt time.Time  `json:"updatedAt"`
}
