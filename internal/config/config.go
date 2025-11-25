package config

import (
	"os"
)

// Config holds all configuration for the application
type Config struct {
	Port            string
	DatabaseURL     string
	JWTSecret       string
	GoogleClientID  string
	GoogleSecret    string
	GoogleRedirect  string
	AppleClientID   string
	AppleTeamID     string
	AppleKeyID      string
	ApplePrivateKey string
	AppleRedirect   string
}

// Load loads configuration from environment variables
func Load() *Config {
	return &Config{
		Port:            getEnv("PORT", "8080"),
		DatabaseURL:     getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/oauth_service?sslmode=disable"),
		JWTSecret:       getEnv("JWT_SECRET", "your-secret-key"),
		GoogleClientID:  getEnv("GOOGLE_CLIENT_ID", ""),
		GoogleSecret:    getEnv("GOOGLE_CLIENT_SECRET", ""),
		GoogleRedirect:  getEnv("GOOGLE_REDIRECT_URL", "http://localhost:8080/auth/google/callback"),
		AppleClientID:   getEnv("APPLE_CLIENT_ID", ""),
		AppleTeamID:     getEnv("APPLE_TEAM_ID", ""),
		AppleKeyID:      getEnv("APPLE_KEY_ID", ""),
		ApplePrivateKey: getEnv("APPLE_PRIVATE_KEY", ""),
		AppleRedirect:   getEnv("APPLE_REDIRECT_URL", "http://localhost:8080/auth/apple/callback"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
