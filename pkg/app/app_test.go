package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
)

type mockServer struct {
	*httptest.Server
}

var ms *mockServer

func TestMain(m *testing.M) {
	ms = setupMockServer()
	defer ms.Close()
	os.Exit(m.Run())
}

func setupMockServer() *mockServer {
	mux := http.NewServeMux()

	mux.HandleFunc("/app/installations/123/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		if _, err := w.Write([]byte(`{"token":"mocked_token"}`)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/orgs/testorg/installation", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"id":123}`)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/repos/testowner/testrepo/installation", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"id":123}`)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/users/testuser/installation", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"id":123}`)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	return &mockServer{
		Server: httptest.NewServer(mux),
	}
}

func setMockServerURL(t *testing.T, app *AppToken) {
	t.Helper()
	baseURL, err := url.Parse(ms.URL + "/")
	if err != nil {
		t.Fatalf("Failed to parse server URL: %v", err)
	}
	app.client.BaseURL = baseURL
}

func setupTestPrivateKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()

	// Generate a test private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test private key: %v", err)
	}

	// Create a temporary file for the private key
	tmpFile, err := os.CreateTemp("", "test-private-key-*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() {
		if err := tmpFile.Close(); err != nil {
			t.Errorf("Failed to close temp file: %v", err)
		}
	}()

	// Encode the private key to PEM format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Write the private key to the temporary file
	if _, err := tmpFile.Write(privateKeyPEM); err != nil {
		t.Fatalf("Failed to write private key to temp file: %v", err)
	}

	return privateKey, tmpFile.Name()
}

func Test_generateJWT(t *testing.T) {
	_, keyPath := setupTestPrivateKey(t)
	defer func() {
		if err := os.Remove(keyPath); err != nil {
			t.Errorf("Failed to remove key file: %v", err)
		}
	}()

	tests := []struct {
		name    string
		appID   int64
		keyPath string
		wantErr bool
	}{
		{"valid", 12345, keyPath, false},
		{"invalid file", 12345, "notfound.pem", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := generateJWT(tt.appID, tt.keyPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("generateJWT() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && token == "" {
				t.Error("generateJWT() returned empty token")
			}
		})
	}
}

func TestNew(t *testing.T) {
	_, keyPath := setupTestPrivateKey(t)
	defer func() {
		if err := os.Remove(keyPath); err != nil {
			t.Errorf("Failed to remove key file: %v", err)
		}
	}()

	_, err := New(12345, keyPath)
	if err != nil {
		t.Errorf("New() error = %v, want nil", err)
	}

	_, err = New(12345, "notfound.pem")
	if err == nil {
		t.Error("New() error = nil, want error for missing key file")
	}
}

func TestAppToken_GetTokenFromOrg(t *testing.T) {
	_, keyPath := setupTestPrivateKey(t)
	defer func() {
		if err := os.Remove(keyPath); err != nil {
			t.Errorf("Failed to remove key file: %v", err)
		}
	}()
	app, err := New(12345, keyPath)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	ctx := context.Background()

	tests := []struct {
		name      string
		org       string
		wantToken string
		wantErr   bool
	}{
		{
			name:      "Error: empty org",
			org:       "",
			wantToken: "",
			wantErr:   true,
		},
		{
			name:      "Success: returns valid token",
			org:       "testorg",
			wantToken: "mocked_token",
			wantErr:   false,
		},
		{
			name:      "Error: not found",
			org:       "notfound",
			wantToken: "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.org == "" {
				_, err := app.GetTokenFromOrg(ctx, tt.org)
				if err == nil {
					t.Error("GetTokenFromOrg() error = nil, want error for empty org")
				}
				return
			}
			setMockServerURL(t, app)

			got, err := app.GetTokenFromOrg(ctx, tt.org)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetTokenFromOrg() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.wantToken {
				t.Errorf("GetTokenFromOrg() = %v, want %v", got, tt.wantToken)
			}
		})
	}
}

func TestAppToken_GetTokenFromRepo(t *testing.T) {
	_, keyPath := setupTestPrivateKey(t)
	defer func() {
		if err := os.Remove(keyPath); err != nil {
			t.Errorf("Failed to remove key file: %v", err)
		}
	}()
	app, err := New(12345, keyPath)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	ctx := context.Background()

	tests := []struct {
		name      string
		owner     string
		repo      string
		wantToken string
		wantErr   bool
	}{
		{
			name:      "Error: empty owner",
			owner:     "",
			repo:      "repo",
			wantToken: "",
			wantErr:   true,
		},
		{
			name:      "Error: empty repo",
			owner:     "owner",
			repo:      "",
			wantToken: "",
			wantErr:   true,
		},
		{
			name:      "Success: returns valid token",
			owner:     "testowner",
			repo:      "testrepo",
			wantToken: "mocked_token",
			wantErr:   false,
		},
		{
			name:      "Error: owner/repo not found",
			owner:     "notfound",
			repo:      "repo",
			wantToken: "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.owner == "" || tt.repo == "" {
				_, err := app.GetTokenFromRepo(ctx, tt.owner, tt.repo)
				if err == nil {
					t.Error("GetTokenFromRepo() error = nil, want error for empty owner or repo")
				}
				return
			}
			setMockServerURL(t, app)

			got, err := app.GetTokenFromRepo(ctx, tt.owner, tt.repo)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetTokenFromRepo() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.wantToken {
				t.Errorf("GetTokenFromRepo() = %v, want %v", got, tt.wantToken)
			}
		})
	}
}

func TestAppToken_GetTokenFromUser(t *testing.T) {
	_, keyPath := setupTestPrivateKey(t)
	defer func() {
		if err := os.Remove(keyPath); err != nil {
			t.Errorf("Failed to remove key file: %v", err)
		}
	}()
	app, err := New(12345, keyPath)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	ctx := context.Background()

	tests := []struct {
		name      string
		user      string
		wantToken string
		wantErr   bool
	}{
		{
			name:      "Error: empty user",
			user:      "",
			wantToken: "",
			wantErr:   true,
		},
		{
			name:      "Success: returns valid token",
			user:      "testuser",
			wantToken: "mocked_token",
			wantErr:   false,
		},
		{
			name:      "Error: user not found",
			user:      "servererror",
			wantToken: "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.user == "" {
				_, err := app.GetTokenFromUser(ctx, tt.user)
				if err == nil {
					t.Error("GetTokenFromUser() error = nil, want error for empty user")
				}
				return
			}

			setMockServerURL(t, app)

			got, err := app.GetTokenFromUser(ctx, tt.user)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetTokenFromUser() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.wantToken {
				t.Errorf("GetTokenFromUser() = %v, want %v", got, tt.wantToken)
			}
		})
	}
}

func TestAppToken_GetToken(t *testing.T) {
	_, keyPath := setupTestPrivateKey(t)
	defer func() {
		if err := os.Remove(keyPath); err != nil {
			t.Errorf("Failed to remove key file: %v", err)
		}
	}()
	app, err := New(12345, keyPath)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	ctx := context.Background()

	tests := []struct {
		name           string
		installationID int64
		wantToken      string
		wantErr        bool
	}{
		{
			name:           "Success: returns valid token",
			installationID: 123,
			wantToken:      "mocked_token",
			wantErr:        false,
		},
		{
			name:           "Error: installation not found",
			installationID: 321,
			wantToken:      "",
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setMockServerURL(t, app)

			got, err := app.GetToken(ctx, tt.installationID)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetToken() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.wantToken {
				t.Errorf("GetToken() = %v, want %v", got, tt.wantToken)
			}
		})
	}
}
