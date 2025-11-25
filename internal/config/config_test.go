package config

import (
	"os"
	"testing"
)

func TestLoad(t *testing.T) {
	// Test default values
	cfg := Load()

	if cfg.Port != "8080" {
		t.Errorf("expected default port 8080, got %s", cfg.Port)
	}

	// Test environment variable override
	os.Setenv("PORT", "9090")
	defer os.Unsetenv("PORT")

	cfg = Load()
	if cfg.Port != "9090" {
		t.Errorf("expected port 9090, got %s", cfg.Port)
	}
}

func TestGetEnv(t *testing.T) {
	// Test default value
	result := getEnv("NONEXISTENT_VAR", "default")
	if result != "default" {
		t.Errorf("expected 'default', got '%s'", result)
	}

	// Test environment variable
	os.Setenv("TEST_VAR", "test_value")
	defer os.Unsetenv("TEST_VAR")

	result = getEnv("TEST_VAR", "default")
	if result != "test_value" {
		t.Errorf("expected 'test_value', got '%s'", result)
	}
}
