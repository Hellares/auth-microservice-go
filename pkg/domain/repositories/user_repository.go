package repositories

import (
	"context"

	"auth-microservice/pkg/domain/entities"

	"github.com/google/uuid"
)

type UserRepository interface {
	Create(ctx context.Context, user *entities.User) error
	FindByID(ctx context.Context, id uuid.UUID) (*entities.User, error)
	FindByDNI(ctx context.Context, dni string) (*entities.User, error)
	FindByEmail(ctx context.Context, email string) (*entities.User, error)
	FindByPhone(ctx context.Context, phone string) (*entities.User, error)
	Update(ctx context.Context, user *entities.User) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, offset, limit int) ([]*entities.User, int, error)
	UpdatePassword(ctx context.Context, id uuid.UUID, password string) error
	VerifyEmail(ctx context.Context, id uuid.UUID) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status entities.UserStatus) error
	UpdateLastLogin(ctx context.Context, id uuid.UUID) error
}
