package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// mockServer represents a mock GitHub API server
type mockServer struct {
	*httptest.Server
	installationID int64
	token          string
}

func newMockServer(t *testing.T) *mockServer {
	t.Helper()

	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)

	mock := &mockServer{
		Server:         server,
		installationID: 12345,
		token:          "mock-token",
	}

	// Mock installation endpoints
	mux.HandleFunc("/api/v3/orgs/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := json.NewEncoder(w).Encode(installationResponse{ID: mock.installationID}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	mux.HandleFunc("/api/v3/repos/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := json.NewEncoder(w).Encode(installationResponse{ID: mock.installationID}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	mux.HandleFunc("/api/v3/users/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := json.NewEncoder(w).Encode(installationResponse{ID: mock.installationID}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	// Mock installation token endpoint
	mux.HandleFunc("/api/v3/app/installations/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := json.NewEncoder(w).Encode(installationTokenResponse{Token: mock.token}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	return mock
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

func TestLoadPrivateKey(t *testing.T) {
	privateKey, keyPath := setupTestPrivateKey(t)
	defer func() {
		if err := os.Remove(keyPath); err != nil {
			t.Errorf("Failed to remove temp file: %v", err)
		}
	}()

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "valid private key",
			path:    keyPath,
			wantErr: false,
		},
		{
			name:    "non-existent file",
			path:    "non-existent.pem",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadPrivateKey(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got == nil {
					t.Error("LoadPrivateKey() returned nil private key")
					return
				}
				// Compare the modulus of the private keys
				if got.N.Cmp(privateKey.N) != 0 {
					t.Error("LoadPrivateKey() returned different private key")
				}
			}
		})
	}
}

func TestGenerateJWT(t *testing.T) {
	privateKey, keyPath := setupTestPrivateKey(t)
	defer func() {
		if err := os.Remove(keyPath); err != nil {
			t.Errorf("Failed to remove temp file: %v", err)
		}
	}()

	tests := []struct {
		name       string
		appID      int64
		privateKey *rsa.PrivateKey
		wantErr    bool
	}{
		{
			name:       "valid input",
			appID:      12345,
			privateKey: privateKey,
			wantErr:    false,
		},
		{
			name:       "zero app ID",
			appID:      0,
			privateKey: privateKey,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateJWT(tt.appID, tt.privateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateJWT() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && token == "" {
				t.Error("GenerateJWT() returned empty token")
			}
		})
	}
}

func TestGetInstallationIDFromOrg(t *testing.T) {
	mock := newMockServer(t)
	defer mock.Close()

	// Override the host for testing
	originalHost := os.Getenv("GH_HOST")
	if err := os.Setenv("GH_HOST", strings.TrimPrefix(mock.URL, "https://")); err != nil {
		t.Fatalf("Failed to set GH_HOST: %v", err)
	}
	defer func() {
		if err := os.Setenv("GH_HOST", originalHost); err != nil {
			t.Errorf("Failed to restore GH_HOST: %v", err)
		}
	}()

	// Configure client to accept self-signed certificates
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	tests := []struct {
		name     string
		jwtToken string
		org      string
		wantErr  bool
	}{
		{
			name:     "empty org",
			jwtToken: "test-token",
			org:      "",
			wantErr:  true,
		},
		{
			name:     "valid org",
			jwtToken: "test-token",
			org:      "test-org",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetInstallationIDFromOrg(tt.jwtToken, tt.org)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetInstallationIDFromOrg() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != mock.installationID {
				t.Errorf("GetInstallationIDFromOrg() = %v, want %v", got, mock.installationID)
			}
		})
	}
}

func TestGetInstallationIDFromRepo(t *testing.T) {
	mock := newMockServer(t)
	defer mock.Close()

	// Override the host for testing
	originalHost := os.Getenv("GH_HOST")
	if err := os.Setenv("GH_HOST", strings.TrimPrefix(mock.URL, "https://")); err != nil {
		t.Fatalf("Failed to set GH_HOST: %v", err)
	}
	defer func() {
		if err := os.Setenv("GH_HOST", originalHost); err != nil {
			t.Errorf("Failed to restore GH_HOST: %v", err)
		}
	}()

	// Configure client to accept self-signed certificates
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	tests := []struct {
		name     string
		jwtToken string
		repo     string
		wantErr  bool
	}{
		{
			name:     "empty repo",
			jwtToken: "test-token",
			repo:     "",
			wantErr:  true,
		},
		{
			name:     "invalid repo format",
			jwtToken: "test-token",
			repo:     "invalid-repo",
			wantErr:  true,
		},
		{
			name:     "valid repo",
			jwtToken: "test-token",
			repo:     "owner/repo",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetInstallationIDFromRepo(tt.jwtToken, tt.repo)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetInstallationIDFromRepo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != mock.installationID {
				t.Errorf("GetInstallationIDFromRepo() = %v, want %v", got, mock.installationID)
			}
		})
	}
}

func TestGetInstallationIDFromUser(t *testing.T) {
	mock := newMockServer(t)
	defer mock.Close()

	// Override the host for testing
	originalHost := os.Getenv("GH_HOST")
	if err := os.Setenv("GH_HOST", strings.TrimPrefix(mock.URL, "https://")); err != nil {
		t.Fatalf("Failed to set GH_HOST: %v", err)
	}
	defer func() {
		if err := os.Setenv("GH_HOST", originalHost); err != nil {
			t.Errorf("Failed to restore GH_HOST: %v", err)
		}
	}()

	// Configure client to accept self-signed certificates
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	tests := []struct {
		name     string
		jwtToken string
		user     string
		wantErr  bool
	}{
		{
			name:     "empty user",
			jwtToken: "test-token",
			user:     "",
			wantErr:  true,
		},
		{
			name:     "valid user",
			jwtToken: "test-token",
			user:     "test-user",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetInstallationIDFromUser(tt.jwtToken, tt.user)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetInstallationIDFromUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != mock.installationID {
				t.Errorf("GetInstallationIDFromUser() = %v, want %v", got, mock.installationID)
			}
		})
	}
}

func TestGetInstallationToken(t *testing.T) {
	mock := newMockServer(t)
	defer mock.Close()

	// Override the host for testing
	originalHost := os.Getenv("GH_HOST")
	if err := os.Setenv("GH_HOST", strings.TrimPrefix(mock.URL, "https://")); err != nil {
		t.Fatalf("Failed to set GH_HOST: %v", err)
	}
	defer func() {
		if err := os.Setenv("GH_HOST", originalHost); err != nil {
			t.Errorf("Failed to restore GH_HOST: %v", err)
		}
	}()

	// Configure client to accept self-signed certificates
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	tests := []struct {
		name           string
		jwtToken       string
		installationID int64
		wantErr        bool
	}{
		{
			name:           "zero installation ID",
			jwtToken:       "test-token",
			installationID: 0,
			wantErr:        false,
		},
		{
			name:           "valid installation ID",
			jwtToken:       "test-token",
			installationID: 12345,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetInstallationToken(tt.jwtToken, tt.installationID)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetInstallationToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != mock.token {
				t.Errorf("GetInstallationToken() = %v, want %v", got, mock.token)
			}
		})
	}
}
