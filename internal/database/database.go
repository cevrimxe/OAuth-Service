package database

import (
	"context"
	"database/sql"
	"time"

	"github.com/cevrimxe/OAuth-Service/internal/models"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// DB wraps the database connection
type DB struct {
	*sql.DB
}

// New creates a new database connection
func New(databaseURL string) (*DB, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &DB{db}, nil
}

// Migrate runs database migrations
func (db *DB) Migrate() error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		email VARCHAR(255) UNIQUE NOT NULL,
		name VARCHAR(255),
		provider VARCHAR(50) NOT NULL,
		provider_id VARCHAR(255) NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(provider, provider_id)
	);

	CREATE TABLE IF NOT EXISTS oauth_tokens (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		provider VARCHAR(50) NOT NULL,
		access_token TEXT,
		refresh_token TEXT,
		expires_at TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(user_id, provider)
	);

	CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
	CREATE INDEX IF NOT EXISTS idx_users_provider ON users(provider, provider_id);
	CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user_id ON oauth_tokens(user_id);
	`

	_, err := db.Exec(query)
	return err
}

// GetUserByProviderID retrieves a user by provider and provider ID
func (db *DB) GetUserByProviderID(ctx context.Context, provider, providerID string) (*models.User, error) {
	user := &models.User{}
	query := `SELECT id, email, name, provider, provider_id, created_at, updated_at 
			  FROM users WHERE provider = $1 AND provider_id = $2`

	err := db.QueryRowContext(ctx, query, provider, providerID).Scan(
		&user.ID, &user.Email, &user.Name, &user.Provider, &user.ProviderID,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// CreateUser creates a new user
func (db *DB) CreateUser(ctx context.Context, user *models.User) error {
	user.ID = uuid.New().String()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	query := `INSERT INTO users (id, email, name, provider, provider_id, created_at, updated_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := db.ExecContext(ctx, query,
		user.ID, user.Email, user.Name, user.Provider, user.ProviderID,
		user.CreatedAt, user.UpdatedAt,
	)
	return err
}

// UpsertOAuthToken creates or updates OAuth tokens for a user
func (db *DB) UpsertOAuthToken(ctx context.Context, token *models.OAuthToken) error {
	token.ID = uuid.New().String()
	token.CreatedAt = time.Now()
	token.UpdatedAt = time.Now()

	query := `INSERT INTO oauth_tokens (id, user_id, provider, access_token, refresh_token, expires_at, created_at, updated_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			  ON CONFLICT (user_id, provider) DO UPDATE SET
			  access_token = EXCLUDED.access_token,
			  refresh_token = EXCLUDED.refresh_token,
			  expires_at = EXCLUDED.expires_at,
			  updated_at = EXCLUDED.updated_at`

	_, err := db.ExecContext(ctx, query,
		token.ID, token.UserID, token.Provider, token.AccessToken,
		token.RefreshToken, token.ExpiresAt, token.CreatedAt, token.UpdatedAt,
	)
	return err
}

// GetUserByID retrieves a user by ID
func (db *DB) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	user := &models.User{}
	query := `SELECT id, email, name, provider, provider_id, created_at, updated_at 
			  FROM users WHERE id = $1`

	err := db.QueryRowContext(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.Name, &user.Provider, &user.ProviderID,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}
