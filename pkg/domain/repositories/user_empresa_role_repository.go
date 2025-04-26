package repositories

import (
	"context"

	"github.com/google/uuid"
	"auth-microservice/pkg/domain/entities"
)

type UserEmpresaRoleRepository interface {
	Create(ctx context.Context, userEmpresaRole *entities.UserEmpresaRole) error
	FindByID(ctx context.Context, id uuid.UUID) (*entities.UserEmpresaRole, error)
	FindByUserAndEmpresa(ctx context.Context, userID, empresaID uuid.UUID) ([]*entities.UserEmpresaRole, error)
	FindByEmpresa(ctx context.Context, empresaID uuid.UUID) ([]*entities.UserEmpresaRole, error)
	FindByRole(ctx context.Context, roleID uuid.UUID) ([]*entities.UserEmpresaRole, error)
	Update(ctx context.Context, userEmpresaRole *entities.UserEmpresaRole) error
	Delete(ctx context.Context, id uuid.UUID) error
	AssignRoleToUser(ctx context.Context, userID, empresaID, roleID uuid.UUID) error
	RemoveRoleFromUser(ctx context.Context, userID, empresaID, roleID uuid.UUID) error
}