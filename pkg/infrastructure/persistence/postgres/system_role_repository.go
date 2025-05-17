// En pkg/infrastructure/persistence/postgres/system_role_repository.go
package postgres

import (
    "context"
    // "database/sql"
    // "errors"
    // "time"
    
    "github.com/google/uuid"
    "github.com/jmoiron/sqlx"
    
    "auth-microservice/pkg/domain/entities"
)

type systemRoleRepository struct {
    db *sqlx.DB
}

func NewSystemRoleRepository(db *sqlx.DB) *systemRoleRepository {
    return &systemRoleRepository{
        db: db,
    }
}

// Implementar el método Create
func (r *systemRoleRepository) Create(ctx context.Context, systemRole *entities.SystemRole) error {
    query := `
        INSERT INTO system_roles (id, user_id, role_name, active, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6)
    `
    
    _, err := r.db.ExecContext(
        ctx,
        query,
        systemRole.ID,
        systemRole.UserID,
        systemRole.RoleName,
        systemRole.Active,
        systemRole.CreatedAt,
        systemRole.UpdatedAt,
    )
    
    return err
}

// Implementar el método FindByUserID
func (r *systemRoleRepository) FindByUserID(ctx context.Context, userID uuid.UUID) ([]*entities.SystemRole, error) {
    query := `
        SELECT id, user_id, role_name, active, created_at, updated_at
        FROM system_roles
        WHERE user_id = $1 AND active = true
    `
    
    rows, err := r.db.QueryContext(ctx, query, userID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    var systemRoles []*entities.SystemRole
    for rows.Next() {
        var role entities.SystemRole
        err := rows.Scan(
            &role.ID,
            &role.UserID,
            &role.RoleName,
            &role.Active,
            &role.CreatedAt,
            &role.UpdatedAt,
        )
        if err != nil {
            return nil, err
        }
        systemRoles = append(systemRoles, &role)
    }
    
    if err = rows.Err(); err != nil {
        return nil, err
    }
    
    return systemRoles, nil
}

// Implementar el método HasSystemRole
func (r *systemRoleRepository) HasSystemRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error) {
    query := `
        SELECT COUNT(*) 
        FROM system_roles 
        WHERE user_id = $1 AND role_name = $2 AND active = true
    `
    
    var count int
    err := r.db.QueryRowContext(ctx, query, userID, roleName).Scan(&count)
    if err != nil {
        return false, err
    }
    
    return count > 0, nil
}

// Implementar el método Delete
func (r *systemRoleRepository) Delete(ctx context.Context, id uuid.UUID) error {
    query := `DELETE FROM system_roles WHERE id = $1`
    _, err := r.db.ExecContext(ctx, query, id)
    return err
}