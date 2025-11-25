package main

import (
	"log"
	"net/http"

	"github.com/cevrimxe/OAuth-Service/internal/config"
	"github.com/cevrimxe/OAuth-Service/internal/database"
	"github.com/cevrimxe/OAuth-Service/internal/handlers"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Connect to database
	db, err := database.New(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Run migrations
	if err := db.Migrate(); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Create handler
	h := handlers.NewHandler(db, cfg)

	// Setup routes
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("GET /health", h.HealthCheck)

	// OAuth routes
	mux.HandleFunc("GET /auth/google", h.GoogleLogin)
	mux.HandleFunc("GET /auth/google/callback", h.GoogleCallback)
	mux.HandleFunc("GET /auth/apple", h.AppleLogin)
	mux.HandleFunc("POST /auth/apple/callback", h.AppleCallback)

	// Protected routes
	mux.Handle("GET /api/user", h.AuthMiddleware(http.HandlerFunc(h.GetUser)))

	// Start server
	log.Printf("Server starting on port %s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
