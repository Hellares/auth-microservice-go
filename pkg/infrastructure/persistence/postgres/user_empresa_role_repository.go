// pkg/infrastructure/persistence/postgres/user_empresa_role_repository.go
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"auth-microservice/pkg/domain/entities"
)

type userEmpresaRoleRepository struct {
	db *sqlx.DB
}

// NewUserEmpresaRoleRepository crea una nueva instancia del repositorio
func NewUserEmpresaRoleRepository(db *sqlx.DB) *userEmpresaRoleRepository {
	return &userEmpresaRoleRepository{
		db: db,
	}
}

func (r *userEmpresaRoleRepository) Create(ctx context.Context, userEmpresaRole *entities.UserEmpresaRole) error {
	query := `
		INSERT INTO user_empresa_roles (id, user_id, empresa_id, role_id, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		userEmpresaRole.ID,
		userEmpresaRole.UserID,
		userEmpresaRole.EmpresaID,
		userEmpresaRole.RoleID,
		userEmpresaRole.Active,
		userEmpresaRole.CreatedAt,
		userEmpresaRole.UpdatedAt,
	)

	return err
}

func (r *userEmpresaRoleRepository) FindByID(ctx context.Context, id uuid.UUID) (*entities.UserEmpresaRole, error) {
	query := `
		SELECT id, user_id, empresa_id, role_id, active, created_at, updated_at
		FROM user_empresa_roles
		WHERE id = $1
	`

	var userEmpresaRole entities.UserEmpresaRole
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&userEmpresaRole.ID,
		&userEmpresaRole.UserID,
		&userEmpresaRole.EmpresaID,
		&userEmpresaRole.RoleID,
		&userEmpresaRole.Active,
		&userEmpresaRole.CreatedAt,
		&userEmpresaRole.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("relación usuario-empresa-rol no encontrada")
		}
		return nil, err
	}

	return &userEmpresaRole, nil
}

func (r *userEmpresaRoleRepository) FindByUserAndEmpresa(ctx context.Context, userID, empresaID uuid.UUID) ([]*entities.UserEmpresaRole, error) {
	query := `
		SELECT id, user_id, empresa_id, role_id, active, created_at, updated_at
		FROM user_empresa_roles
		WHERE user_id = $1 AND empresa_id = $2
	`

	rows, err := r.db.QueryContext(ctx, query, userID, empresaID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	userEmpresaRoles := []*entities.UserEmpresaRole{}
	for rows.Next() {
		var userEmpresaRole entities.UserEmpresaRole
		err := rows.Scan(
			&userEmpresaRole.ID,
			&userEmpresaRole.UserID,
			&userEmpresaRole.EmpresaID,
			&userEmpresaRole.RoleID,
			&userEmpresaRole.Active,
			&userEmpresaRole.CreatedAt,
			&userEmpresaRole.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		userEmpresaRoles = append(userEmpresaRoles, &userEmpresaRole)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return userEmpresaRoles, nil
}

func (r *userEmpresaRoleRepository) FindByEmpresa(ctx context.Context, empresaID uuid.UUID) ([]*entities.UserEmpresaRole, error) {
	query := `
		SELECT id, user_id, empresa_id, role_id, active, created_at, updated_at
		FROM user_empresa_roles
		WHERE empresa_id = $1
	`

	rows, err := r.db.QueryContext(ctx, query, empresaID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	userEmpresaRoles := []*entities.UserEmpresaRole{}
	for rows.Next() {
		var userEmpresaRole entities.UserEmpresaRole
		err := rows.Scan(
			&userEmpresaRole.ID,
			&userEmpresaRole.UserID,
			&userEmpresaRole.EmpresaID,
			&userEmpresaRole.RoleID,
			&userEmpresaRole.Active,
			&userEmpresaRole.CreatedAt,
			&userEmpresaRole.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		userEmpresaRoles = append(userEmpresaRoles, &userEmpresaRole)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return userEmpresaRoles, nil
}

func (r *userEmpresaRoleRepository) FindByRole(ctx context.Context, roleID uuid.UUID) ([]*entities.UserEmpresaRole, error) {
	query := `
		SELECT id, user_id, empresa_id, role_id, active, created_at, updated_at
		FROM user_empresa_roles
		WHERE role_id = $1
	`

	rows, err := r.db.QueryContext(ctx, query, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	userEmpresaRoles := []*entities.UserEmpresaRole{}
	for rows.Next() {
		var userEmpresaRole entities.UserEmpresaRole
		err := rows.Scan(
			&userEmpresaRole.ID,
			&userEmpresaRole.UserID,
			&userEmpresaRole.EmpresaID,
			&userEmpresaRole.RoleID,
			&userEmpresaRole.Active,
			&userEmpresaRole.CreatedAt,
			&userEmpresaRole.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		userEmpresaRoles = append(userEmpresaRoles, &userEmpresaRole)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return userEmpresaRoles, nil
}

func (r *userEmpresaRoleRepository) Update(ctx context.Context, userEmpresaRole *entities.UserEmpresaRole) error {
	query := `
		UPDATE user_empresa_roles
		SET user_id = $1, empresa_id = $2, role_id = $3, active = $4, updated_at = $5
		WHERE id = $6
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		userEmpresaRole.UserID,
		userEmpresaRole.EmpresaID,
		userEmpresaRole.RoleID,
		userEmpresaRole.Active,
		time.Now(),
		userEmpresaRole.ID,
	)

	return err
}

func (r *userEmpresaRoleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM user_empresa_roles WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *userEmpresaRoleRepository) AssignRoleToUser(ctx context.Context, userID, empresaID, roleID uuid.UUID) error {
	// Verificar si ya existe la relación
	existingRoles, err := r.FindByUserAndEmpresa(ctx, userID, empresaID)
	if err == nil && len(existingRoles) > 0 {
		for _, existing := range existingRoles {
			if existing.RoleID == roleID {
				if !existing.Active {
					// Si existe pero está inactivo, lo activamos
					existing.Active = true
					existing.UpdatedAt = time.Now()
					return r.Update(ctx, existing)
				}
				return errors.New("el usuario ya tiene este rol en la empresa")
			}
		}
	}

	// Crear nueva relación
	userEmpresaRole := &entities.UserEmpresaRole{
		ID:        uuid.New(),
		UserID:    userID,
		EmpresaID: empresaID,
		RoleID:    roleID,
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return r.Create(ctx, userEmpresaRole)
}

func (r *userEmpresaRoleRepository) RemoveRoleFromUser(ctx context.Context, userID, empresaID, roleID uuid.UUID) error {
	query := `
		DELETE FROM user_empresa_roles 
		WHERE user_id = $1 AND empresa_id = $2 AND role_id = $3
	`

	_, err := r.db.ExecContext(ctx, query, userID, empresaID, roleID)
	return err
}

func (r *userEmpresaRoleRepository) FindEmpresasByUserID(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	var empresaIDs []uuid.UUID
	query := `
		SELECT DISTINCT empresa_id
		FROM user_empresa_roles
		WHERE user_id = $1 AND active = true
	`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var empresaID uuid.UUID
		if err := rows.Scan(&empresaID); err != nil {
			return nil, err
		}
		empresaIDs = append(empresaIDs, empresaID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return empresaIDs, nil

}

func (r *userEmpresaRoleRepository) GetUsersByEmpresa(ctx context.Context, empresaID uuid.UUID, roleFilter string) ([]uuid.UUID, error) {
    var query string
    var args []interface{}
    
    if roleFilter != "" {
        query = `
            SELECT uer.user_id, MIN(uer.created_at) as min_created_at
            FROM user_empresa_roles uer
            JOIN roles r ON uer.role_id = r.id
            WHERE uer.empresa_id = $1 AND uer.active = true AND r.name = $2
            GROUP BY uer.user_id
            ORDER BY min_created_at
        `
        args = []interface{}{empresaID, roleFilter}
    } else {
        query = `
            SELECT user_id, MIN(created_at) as min_created_at
            FROM user_empresa_roles 
            WHERE empresa_id = $1 AND active = true
            GROUP BY user_id
            ORDER BY min_created_at
        `
        args = []interface{}{empresaID}
    }
    
    rows, err := r.db.QueryContext(ctx, query, args...)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    var userIDs []uuid.UUID
    for rows.Next() {
        var userID uuid.UUID
        var createdAt time.Time
        if err := rows.Scan(&userID, &createdAt); err != nil {
            return nil, err
        }
        userIDs = append(userIDs, userID)
    }
    
    return userIDs, nil
}

func (r *userEmpresaRoleRepository) FindByUserID(ctx context.Context, userID uuid.UUID) ([]*entities.UserEmpresaRole, error) {
    query := `
        SELECT id, user_id, empresa_id, role_id, active, created_at, updated_at
        FROM user_empresa_roles
        WHERE user_id = $1 AND active = true
    `
    
    rows, err := r.db.QueryContext(ctx, query, userID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    userEmpresaRoles := []*entities.UserEmpresaRole{}
    for rows.Next() {
        var uer entities.UserEmpresaRole
        err := rows.Scan(
            &uer.ID,
            &uer.UserID,
            &uer.EmpresaID,
            &uer.RoleID,
            &uer.Active,
            &uer.CreatedAt,
            &uer.UpdatedAt,
        )
        if err != nil {
            return nil, err
        }
        userEmpresaRoles = append(userEmpresaRoles, &uer)
    }
    
    if err = rows.Err(); err != nil {
        return nil, err
    }
    
    return userEmpresaRoles, nil
}

func (r *userEmpresaRoleRepository) GetAllUsersByEmpresa(ctx context.Context, empresaID uuid.UUID, roleFilter string) ([]uuid.UUID, error) {
    var query string
    var args []interface{}
    
    if roleFilter != "" {
        query = `
            SELECT DISTINCT uer.user_id
            FROM user_empresa_roles uer
            JOIN roles r ON uer.role_id = r.id
            WHERE uer.empresa_id = $1 AND uer.active = true AND r.name = $2
        `
        args = []interface{}{empresaID, roleFilter}
    } else {
        query = `
            SELECT DISTINCT user_id
            FROM user_empresa_roles 
            WHERE empresa_id = $1 AND active = true
        `
        args = []interface{}{empresaID}
    }
    
    rows, err := r.db.QueryContext(ctx, query, args...)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    var userIDs []uuid.UUID
    for rows.Next() {
        var userID uuid.UUID
        if err := rows.Scan(&userID); err != nil {
            return nil, err
        }
        userIDs = append(userIDs, userID)
    }
    
    return userIDs, nil
}

