package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"auth-microservice/pkg/domain/entities"
)

type verificationTokenRepository struct {
	db *sqlx.DB
}

func NewVerificationTokenRepository(db *sqlx.DB) *verificationTokenRepository {
	return &verificationTokenRepository{
		db: db,
	}
}

func (r *verificationTokenRepository) Create(ctx context.Context, token *entities.VerificationToken) error {
	query := `
		INSERT INTO verification_tokens (id, user_id, token, type, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		token.ID,
		token.UserID,
		token.Token,
		token.Type,
		token.ExpiresAt,
		token.CreatedAt,
	)

	return err
}

func (r *verificationTokenRepository) FindByToken(ctx context.Context, token string) (*entities.VerificationToken, error) {
	query := `
		SELECT id, user_id, token, type, expires_at, created_at
		FROM verification_tokens
		WHERE token = $1
	`

	var vt entities.VerificationToken
	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&vt.ID,
		&vt.UserID,
		&vt.Token,
		&vt.Type,
		&vt.ExpiresAt,
		&vt.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("token no encontrado")
		}
		return nil, err
	}

	return &vt, nil
}

func (r *verificationTokenRepository) FindByUserAndType(ctx context.Context, userID uuid.UUID, tokenType entities.TokenType) (*entities.VerificationToken, error) {
	query := `
		SELECT id, user_id, token, type, expires_at, created_at
		FROM verification_tokens
		WHERE user_id = $1 AND type = $2
	`

	var vt entities.VerificationToken
	err := r.db.QueryRowContext(ctx, query, userID, tokenType).Scan(
		&vt.ID,
		&vt.UserID,
		&vt.Token,
		&vt.Type,
		&vt.ExpiresAt,
		&vt.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("token no encontrado")
		}
		return nil, err
	}

	return &vt, nil
}

func (r *verificationTokenRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM verification_tokens WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *verificationTokenRepository) DeleteExpired(ctx context.Context) error {
	query := `DELETE FROM verification_tokens WHERE expires_at < NOW()`
	_, err := r.db.ExecContext(ctx, query)
	return err
}