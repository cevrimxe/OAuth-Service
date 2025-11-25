package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/cevrimxe/OAuth-Service/internal/config"
	"github.com/cevrimxe/OAuth-Service/internal/database"
	"github.com/cevrimxe/OAuth-Service/internal/models"
	"github.com/cevrimxe/OAuth-Service/internal/oauth"
	"github.com/golang-jwt/jwt/v5"
)

// Handler holds dependencies for HTTP handlers
type Handler struct {
	DB       *database.DB
	Config   *config.Config
	Google   *oauth.GoogleProvider
	Apple    *oauth.AppleProvider
}

// NewHandler creates a new handler instance
func NewHandler(db *database.DB, cfg *config.Config) *Handler {
	return &Handler{
		DB:     db,
		Config: cfg,
		Google: oauth.NewGoogleProvider(cfg),
		Apple:  oauth.NewAppleProvider(cfg),
	}
}

// Response represents a standard JSON response
type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// AuthResponse represents the authentication response
type AuthResponse struct {
	Token string       `json:"token"`
	User  *models.User `json:"user"`
}

// sendJSON sends a JSON response
func sendJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

// sendError sends an error response
func sendError(w http.ResponseWriter, statusCode int, message string) {
	sendJSON(w, statusCode, Response{Success: false, Error: message})
}

// sendSuccess sends a success response
func sendSuccess(w http.ResponseWriter, data interface{}) {
	sendJSON(w, http.StatusOK, Response{Success: true, Data: data})
}

// generateJWT generates a JWT token for a user
func (h *Handler) generateJWT(user *models.User) (string, error) {
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"exp":     time.Now().Add(time.Hour * 24 * 7).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(h.Config.JWTSecret))
}

// HealthCheck handles health check requests
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	sendSuccess(w, map[string]string{"status": "healthy"})
}

// GoogleLogin initiates Google OAuth flow
func (h *Handler) GoogleLogin(w http.ResponseWriter, r *http.Request) {
	state := generateState()
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	authURL := h.Google.GetAuthURL(state)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// GoogleCallback handles Google OAuth callback
func (h *Handler) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Verify state
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil {
		sendError(w, http.StatusBadRequest, "missing state cookie")
		return
	}

	if r.URL.Query().Get("state") != stateCookie.Value {
		sendError(w, http.StatusBadRequest, "invalid state")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		sendError(w, http.StatusBadRequest, "missing authorization code")
		return
	}

	// Exchange code for tokens
	tokenResp, err := h.Google.ExchangeCode(ctx, code)
	if err != nil {
		log.Printf("Failed to exchange code: %v", err)
		sendError(w, http.StatusInternalServerError, "failed to exchange authorization code")
		return
	}

	// Get user info
	googleUser, err := h.Google.GetUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		log.Printf("Failed to get user info: %v", err)
		sendError(w, http.StatusInternalServerError, "failed to get user info")
		return
	}

	// Find or create user
	user, err := h.findOrCreateUser(ctx, "google", googleUser.ID, googleUser.Email, googleUser.Name)
	if err != nil {
		log.Printf("Failed to find or create user: %v", err)
		sendError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	// Store tokens
	oauthToken := &models.OAuthToken{
		UserID:       user.ID,
		Provider:     "google",
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}
	if err := h.DB.UpsertOAuthToken(ctx, oauthToken); err != nil {
		log.Printf("Failed to store tokens: %v", err)
	}

	// Generate JWT
	jwtToken, err := h.generateJWT(user)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	sendSuccess(w, AuthResponse{Token: jwtToken, User: user})
}

// AppleLogin initiates Apple Sign In flow
func (h *Handler) AppleLogin(w http.ResponseWriter, r *http.Request) {
	state := generateState()
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})
	authURL := h.Apple.GetAuthURL(state)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// AppleCallback handles Apple Sign In callback
func (h *Handler) AppleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Apple uses POST for form_post response mode
	if err := r.ParseForm(); err != nil {
		sendError(w, http.StatusBadRequest, "failed to parse form")
		return
	}

	// Verify state
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil {
		sendError(w, http.StatusBadRequest, "missing state cookie")
		return
	}

	if r.FormValue("state") != stateCookie.Value {
		sendError(w, http.StatusBadRequest, "invalid state")
		return
	}

	code := r.FormValue("code")
	if code == "" {
		sendError(w, http.StatusBadRequest, "missing authorization code")
		return
	}

	// Exchange code for tokens
	tokenResp, err := h.Apple.ExchangeCode(ctx, code)
	if err != nil {
		log.Printf("Failed to exchange code: %v", err)
		sendError(w, http.StatusInternalServerError, "failed to exchange authorization code")
		return
	}

	// Get user info from ID token
	appleUser, err := h.Apple.GetUserFromIDToken(tokenResp.IDToken)
	if err != nil {
		log.Printf("Failed to get user info: %v", err)
		sendError(w, http.StatusInternalServerError, "failed to get user info")
		return
	}

	// Apple may provide user name only on first authorization
	userName := r.FormValue("user")
	if userName != "" {
		var userInfo struct {
			Name struct {
				FirstName string `json:"firstName"`
				LastName  string `json:"lastName"`
			} `json:"name"`
		}
		if err := json.Unmarshal([]byte(userName), &userInfo); err == nil {
			appleUser.Name = userInfo.Name.FirstName + " " + userInfo.Name.LastName
		}
	}

	// Find or create user
	user, err := h.findOrCreateUser(ctx, "apple", appleUser.ID, appleUser.Email, appleUser.Name)
	if err != nil {
		log.Printf("Failed to find or create user: %v", err)
		sendError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	// Store tokens
	oauthToken := &models.OAuthToken{
		UserID:       user.ID,
		Provider:     "apple",
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}
	if err := h.DB.UpsertOAuthToken(ctx, oauthToken); err != nil {
		log.Printf("Failed to store tokens: %v", err)
	}

	// Generate JWT
	jwtToken, err := h.generateJWT(user)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	sendSuccess(w, AuthResponse{Token: jwtToken, User: user})
}

// findOrCreateUser finds an existing user or creates a new one
func (h *Handler) findOrCreateUser(ctx context.Context, provider, providerID, email, name string) (*models.User, error) {
	user, err := h.DB.GetUserByProviderID(ctx, provider, providerID)
	if err == nil {
		return user, nil
	}

	if err != sql.ErrNoRows {
		return nil, err
	}

	// Create new user
	user = &models.User{
		Email:      email,
		Name:       name,
		Provider:   provider,
		ProviderID: providerID,
	}

	if err := h.DB.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

// GetUser returns the current user info
func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(contextKey("user_id")).(string)

	user, err := h.DB.GetUserByID(r.Context(), userID)
	if err != nil {
		sendError(w, http.StatusNotFound, "user not found")
		return
	}

	sendSuccess(w, user)
}

// generateState generates a random state for OAuth
func generateState() string {
	return time.Now().Format("20060102150405")
}
