package handlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// AuthMiddleware validates JWT tokens
func (h *Handler) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			sendError(w, http.StatusUnauthorized, "missing authorization header")
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			sendError(w, http.StatusUnauthorized, "invalid authorization header format")
			return
		}

		tokenString := parts[1]
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(h.Config.JWTSecret), nil
		})

		if err != nil || !token.Valid {
			sendError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			sendError(w, http.StatusUnauthorized, "invalid token claims")
			return
		}

		userID, ok := claims["user_id"].(string)
		if !ok {
			sendError(w, http.StatusUnauthorized, "invalid user id in token")
			return
		}

		ctx := context.WithValue(r.Context(), contextKey("user_id"), userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// contextKey is a custom type for context keys
type contextKey string
