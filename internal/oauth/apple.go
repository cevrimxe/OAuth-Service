package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cevrimxe/OAuth-Service/internal/config"
	"github.com/golang-jwt/jwt/v5"
)

// AppleProvider handles Apple Sign In
type AppleProvider struct {
	ClientID    string
	TeamID      string
	KeyID       string
	PrivateKey  string
	RedirectURL string
}

// AppleUser represents the user info from Apple
type AppleUser struct {
	ID    string `json:"sub"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// AppleTokenResponse represents the token response from Apple
type AppleTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// AppleIDTokenClaims represents the claims in Apple's ID token
type AppleIDTokenClaims struct {
	jwt.RegisteredClaims
	Email         string `json:"email"`
	EmailVerified any    `json:"email_verified"`
}

// NewAppleProvider creates a new Apple OAuth provider
func NewAppleProvider(cfg *config.Config) *AppleProvider {
	return &AppleProvider{
		ClientID:    cfg.AppleClientID,
		TeamID:      cfg.AppleTeamID,
		KeyID:       cfg.AppleKeyID,
		PrivateKey:  cfg.ApplePrivateKey,
		RedirectURL: cfg.AppleRedirect,
	}
}

// GetAuthURL returns the Apple Sign In authorization URL
func (a *AppleProvider) GetAuthURL(state string) string {
	params := url.Values{}
	params.Add("client_id", a.ClientID)
	params.Add("redirect_uri", a.RedirectURL)
	params.Add("response_type", "code")
	params.Add("scope", "name email")
	params.Add("state", state)
	params.Add("response_mode", "form_post")

	return "https://appleid.apple.com/auth/authorize?" + params.Encode()
}

// generateClientSecret generates the client secret JWT for Apple
func (a *AppleProvider) generateClientSecret() (string, error) {
	block, _ := pem.Decode([]byte(a.PrivateKey))
	if block == nil {
		return "", fmt.Errorf("failed to parse PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("key is not ECDSA")
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": a.TeamID,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour * 24 * 180).Unix(),
		"aud": "https://appleid.apple.com",
		"sub": a.ClientID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = a.KeyID

	return token.SignedString(ecdsaKey)
}

// ExchangeCode exchanges the authorization code for tokens
func (a *AppleProvider) ExchangeCode(ctx context.Context, code string) (*AppleTokenResponse, error) {
	clientSecret, err := a.generateClientSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client secret: %w", err)
	}

	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", a.ClientID)
	data.Set("client_secret", clientSecret)
	data.Set("redirect_uri", a.RedirectURL)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, "POST", "https://appleid.apple.com/auth/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to exchange code: %s", string(body))
	}

	var tokenResp AppleTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// GetUserFromIDToken extracts user information from Apple's ID token
func (a *AppleProvider) GetUserFromIDToken(idToken string) (*AppleUser, error) {
	token, _, err := jwt.NewParser().ParseUnverified(idToken, &AppleIDTokenClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse ID token: %w", err)
	}

	claims, ok := token.Claims.(*AppleIDTokenClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	return &AppleUser{
		ID:    claims.Subject,
		Email: claims.Email,
	}, nil
}
