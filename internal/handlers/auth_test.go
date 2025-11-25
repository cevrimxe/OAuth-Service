package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthCheck(t *testing.T) {
	h := &Handler{}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	h.HealthCheck(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if !resp.Success {
		t.Error("expected success to be true")
	}
}

func TestGenerateState(t *testing.T) {
	state := generateState()
	if state == "" {
		t.Error("expected non-empty state")
	}

	// Verify it's base64url encoded and has reasonable length
	decoded, err := base64.URLEncoding.DecodeString(state)
	if err != nil {
		t.Errorf("expected valid base64url encoded state, got error: %v", err)
	}

	if len(decoded) < 16 {
		t.Error("expected state to be at least 16 bytes when decoded")
	}

	// Verify uniqueness
	state2 := generateState()
	if state == state2 {
		t.Error("expected different states to be generated")
	}
}
