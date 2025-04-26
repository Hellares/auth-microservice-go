package repositories

import (
	"context"

	"github.com/google/uuid"
	"auth-microservice/pkg/domain/entities"
)

type SessionRepository interface {
	Create(ctx context.Context, session *entities.Session) error
	FindByID(ctx context.Context, id uuid.UUID) (*entities.Session, error)
	FindByToken(ctx context.Context, token string) (*entities.Session, error)
	FindByUser(ctx context.Context, userID uuid.UUID) ([]*entities.Session, error)
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteAllForUser(ctx context.Context, userID uuid.UUID) error
	DeleteExpired(ctx context.Context) error
}