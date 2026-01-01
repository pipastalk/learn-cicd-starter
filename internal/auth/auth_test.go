package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("no authorization header", func(t *testing.T) {
		headers := http.Header{}
		_, err := GetAPIKey(headers)
		if err == nil {
			t.Error("expected error for missing header, got nil")
		}
	})

	t.Run("malformed header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer sometoken")
		_, err := GetAPIKey(headers)
		if err == nil {
			t.Error("expected error for malformed header, got nil")
		}
	})

	t.Run("valid ApiKey header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey my-secret-key")
		key, err := GetAPIKey(headers)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if key != "my-secret-key" {
			t.Errorf("expected key 'my-secret-key', got '%s'", key)
		}
	})

	t.Run("ApiKey with no value", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey")
		_, err := GetAPIKey(headers)
		if err == nil {
			t.Error("expected error for missing key value, got nil")
		}
	})
}
