package middleware

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoggingMiddleware(t *testing.T) {
	t.Run("Logs Basic Request Info", func(t *testing.T) {
		var logOutput bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&logOutput, nil))

		// Mock next handler
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("test response"))
		})

		middleware := Logging(nextHandler, *logger)

		req := httptest.NewRequest("GET", "/test-path", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("User-Agent", "test-agent")
		recorder := httptest.NewRecorder()

		middleware.ServeHTTP(recorder, req)

		resp := recorder.Result()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status code to be 200, got %d", resp.StatusCode)
		}

		logText := logOutput.String()

		// Check that log contains expected fields
		expectedFields := []string{
			"/test-path",
			"ip=127.0.0.1:12345",
			"method=GET",
			"status=200",
			"ua=test-agent",
			"duration=",
		}

		for _, field := range expectedFields {
			if !strings.Contains(logText, field) {
				t.Errorf("expected log to contain %q, got: %s", field, logText)
			}
		}

		// Should not contain user field when no email header is set
		if strings.Contains(logText, "user=") {
			t.Errorf("expected log to not contain user field when no email header is set, got: %s", logText)
		}
	})

	t.Run("Logs User Email When Present", func(t *testing.T) {
		var logOutput bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&logOutput, nil))

		// Mock next handler that sets the email header (simulating auth middleware)
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Set(AuthHeader, "test@example.com")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("test response"))
		})

		middleware := Logging(nextHandler, *logger)

		req := httptest.NewRequest("GET", "/authenticated-path", nil)
		req.RemoteAddr = "192.168.1.100:54321"
		recorder := httptest.NewRecorder()

		middleware.ServeHTTP(recorder, req)

		resp := recorder.Result()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status code to be 200, got %d", resp.StatusCode)
		}

		logText := logOutput.String()

		// Check that log contains user email
		if !strings.Contains(logText, "user=test@example.com") {
			t.Errorf("expected log to contain user=test@example.com, got: %s", logText)
		}

		// Check other expected fields are still present
		expectedFields := []string{
			"/authenticated-path",
			"ip=192.168.1.100:54321",
			"method=GET",
			"status=200",
		}

		for _, field := range expectedFields {
			if !strings.Contains(logText, field) {
				t.Errorf("expected log to contain %q, got: %s", field, logText)
			}
		}
	})

	t.Run("Logs Error Status Codes", func(t *testing.T) {
		var logOutput bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&logOutput, nil))

		// Mock next handler that returns an error
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Set(AuthHeader, "user@example.com")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("forbidden"))
		})

		middleware := Logging(nextHandler, *logger)

		req := httptest.NewRequest("POST", "/forbidden-path", nil)
		recorder := httptest.NewRecorder()

		middleware.ServeHTTP(recorder, req)

		resp := recorder.Result()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected status code to be 403, got %d", resp.StatusCode)
		}

		logText := logOutput.String()

		// Check that error status is logged
		if !strings.Contains(logText, "status=403") {
			t.Errorf("expected log to contain status=403, got: %s", logText)
		}

		// Check that user is still logged even with error status
		if !strings.Contains(logText, "user=user@example.com") {
			t.Errorf("expected log to contain user email even with error status, got: %s", logText)
		}
	})
}
