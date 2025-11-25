package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
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

// AppleJWKS represents Apple's JSON Web Key Set
type AppleJWKS struct {
	Keys []AppleJWK `json:"keys"`
}

// AppleJWK represents a single Apple JSON Web Key
type AppleJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

var (
	appleKeysCache     *AppleJWKS
	appleKeysCacheLock sync.RWMutex
	appleKeysCacheTime time.Time
)

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

// GetUserFromIDToken extracts user information from Apple's ID token with proper verification
func (a *AppleProvider) GetUserFromIDToken(ctx context.Context, idToken string) (*AppleUser, error) {
	// Fetch Apple's public keys
	keys, err := a.fetchApplePublicKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Apple public keys: %w", err)
	}

	// Parse the token to get the key ID from header
	token, err := jwt.ParseWithClaims(idToken, &AppleIDTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method - Apple uses RS256
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}

		// Find the matching key
		for _, key := range keys.Keys {
			if key.Kid == kid {
				return a.parseAppleRSAPublicKey(key)
			}
		}

		return nil, fmt.Errorf("no matching key found for kid: %s", kid)
	}, jwt.WithAudience(a.ClientID), jwt.WithIssuer("https://appleid.apple.com"))

	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	claims, ok := token.Claims.(*AppleIDTokenClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return &AppleUser{
		ID:    claims.Subject,
		Email: claims.Email,
	}, nil
}

// fetchApplePublicKeys fetches Apple's public keys for JWT verification
func (a *AppleProvider) fetchApplePublicKeys(ctx context.Context) (*AppleJWKS, error) {
	appleKeysCacheLock.RLock()
	if appleKeysCache != nil && time.Since(appleKeysCacheTime) < time.Hour {
		defer appleKeysCacheLock.RUnlock()
		return appleKeysCache, nil
	}
	appleKeysCacheLock.RUnlock()

	appleKeysCacheLock.Lock()
	defer appleKeysCacheLock.Unlock()

	// Double-check after acquiring write lock
	if appleKeysCache != nil && time.Since(appleKeysCacheTime) < time.Hour {
		return appleKeysCache, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://appleid.apple.com/auth/keys", nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to fetch Apple keys: %s", string(body))
	}

	var keys AppleJWKS
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, err
	}

	appleKeysCache = &keys
	appleKeysCacheTime = time.Now()

	return &keys, nil
}

// parseAppleRSAPublicKey converts an Apple JWK to an RSA public key
func (a *AppleProvider) parseAppleRSAPublicKey(key AppleJWK) (interface{}, error) {
	// Decode the modulus (n) and exponent (e) from base64url
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode N: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode E: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}
