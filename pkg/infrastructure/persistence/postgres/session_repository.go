// pkg/infrastructure/persistence/postgres/session_repository.go
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

type sessionRepository struct {
	db *sqlx.DB
}

// NewSessionRepository crea una nueva instancia del repositorio de sesiones
func NewSessionRepository(db *sqlx.DB) *sessionRepository {
	return &sessionRepository{
		db: db,
	}
}

func (r *sessionRepository) Create(ctx context.Context, session *entities.Session) error {
	query := `
		INSERT INTO sessions (id, user_id, token, ip_address, user_agent, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		session.ID,
		session.UserID,
		session.Token,
		session.IPAddress,
		session.UserAgent,
		session.ExpiresAt,
		session.CreatedAt,
		session.UpdatedAt,
	)

	return err
}

func (r *sessionRepository) FindByID(ctx context.Context, id uuid.UUID) (*entities.Session, error) {
	query := `
		SELECT id, user_id, token, ip_address, user_agent, expires_at, created_at, updated_at
		FROM sessions
		WHERE id = $1
	`

	var session entities.Session
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&session.ID,
		&session.UserID,
		&session.Token,
		&session.IPAddress,
		&session.UserAgent,
		&session.ExpiresAt,
		&session.CreatedAt,
		&session.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("sesión no encontrada")
		}
		return nil, err
	}

	return &session, nil
}

func (r *sessionRepository) FindByToken(ctx context.Context, token string) (*entities.Session, error) {
	query := `
		SELECT id, user_id, token, ip_address, user_agent, expires_at, created_at, updated_at
		FROM sessions
		WHERE token = $1
	`

	var session entities.Session
	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&session.ID,
		&session.UserID,
		&session.Token,
		&session.IPAddress,
		&session.UserAgent,
		&session.ExpiresAt,
		&session.CreatedAt,
		&session.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("sesión no encontrada")
		}
		return nil, err
	}

	return &session, nil
}

func (r *sessionRepository) FindByUser(ctx context.Context, userID uuid.UUID) ([]*entities.Session, error) {
	query := `
		SELECT id, user_id, token, ip_address, user_agent, expires_at, created_at, updated_at
		FROM sessions
		WHERE user_id = $1
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sessions := []*entities.Session{}
	for rows.Next() {
		var session entities.Session
		err := rows.Scan(
			&session.ID,
			&session.UserID,
			&session.Token,
			&session.IPAddress,
			&session.UserAgent,
			&session.ExpiresAt,
			&session.CreatedAt,
			&session.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, &session)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return sessions, nil
}

func (r *sessionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM sessions WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *sessionRepository) DeleteAllForUser(ctx context.Context, userID uuid.UUID) error {
	query := `DELETE FROM sessions WHERE user_id = $1`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

func (r *sessionRepository) DeleteExpired(ctx context.Context) error {
	query := `DELETE FROM sessions WHERE expires_at < $1`
	_, err := r.db.ExecContext(ctx, query, time.Now())
	return err
}