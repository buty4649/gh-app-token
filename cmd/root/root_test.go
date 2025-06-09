package root

import (
	"testing"
)

func TestValidateFlags(t *testing.T) {
	tests := []struct {
		name           string
		appID          int64
		privateKeyPath string
		installationID int64
		org            string
		repo           string
		user           string
		wantErr        bool
		errMsg         string
	}{
		{
			name:           "missing app ID",
			appID:          0,
			privateKeyPath: "test.pem",
			installationID: 123,
			wantErr:        true,
			errMsg:         "app ID is required (--app-id or GH_APP_AUTH_APP_ID)",
		},
		{
			name:           "missing private key path",
			appID:          123,
			privateKeyPath: "",
			installationID: 123,
			wantErr:        true,
			errMsg:         "private key path is required (--private-key or GH_APP_AUTH_PRIVATE_KEY)",
		},
		{
			name:           "no installation ID flags",
			appID:          123,
			privateKeyPath: "test.pem",
			installationID: 0,
			org:            "",
			repo:           "",
			user:           "",
			wantErr:        true,
			errMsg:         "--installation-id, --org, --repo, or --user is required",
		},
		{
			name:           "valid installation ID",
			appID:          123,
			privateKeyPath: "test.pem",
			installationID: 123,
			wantErr:        false,
		},
		{
			name:           "valid org",
			appID:          123,
			privateKeyPath: "test.pem",
			org:            "test-org",
			wantErr:        false,
		},
		{
			name:           "valid repo",
			appID:          123,
			privateKeyPath: "test.pem",
			repo:           "owner/repo",
			wantErr:        false,
		},
		{
			name:           "valid user",
			appID:          123,
			privateKeyPath: "test.pem",
			user:           "test-user",
			wantErr:        false,
		},
		{
			name:           "installation ID with org",
			appID:          123,
			privateKeyPath: "test.pem",
			installationID: 123,
			org:            "test-org",
			wantErr:        true,
			errMsg:         "--installation-id and --org, --repo, or --user cannot be used together",
		},
		{
			name:           "installation ID with repo",
			appID:          123,
			privateKeyPath: "test.pem",
			installationID: 123,
			repo:           "owner/repo",
			wantErr:        true,
			errMsg:         "--installation-id and --org, --repo, or --user cannot be used together",
		},
		{
			name:           "installation ID with user",
			appID:          123,
			privateKeyPath: "test.pem",
			installationID: 123,
			user:           "test-user",
			wantErr:        true,
			errMsg:         "--installation-id and --org, --repo, or --user cannot be used together",
		},
		{
			name:           "org with repo",
			appID:          123,
			privateKeyPath: "test.pem",
			org:            "test-org",
			repo:           "owner/repo",
			wantErr:        true,
			errMsg:         "--org, --repo, or --user cannot be used together",
		},
		{
			name:           "org with user",
			appID:          123,
			privateKeyPath: "test.pem",
			org:            "test-org",
			user:           "test-user",
			wantErr:        true,
			errMsg:         "--org, --repo, or --user cannot be used together",
		},
		{
			name:           "repo with user",
			appID:          123,
			privateKeyPath: "test.pem",
			repo:           "owner/repo",
			user:           "test-user",
			wantErr:        true,
			errMsg:         "--org, --repo, or --user cannot be used together",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set global variables for the test
			appID = tt.appID
			privateKeyPath = tt.privateKeyPath
			installationID = tt.installationID
			org = tt.org
			repo = tt.repo
			user = tt.user

			err := validateFlags()
			if (err != nil) != tt.wantErr {
				t.Errorf("validateFlags() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && err.Error() != tt.errMsg {
				t.Errorf("validateFlags() error message = %v, want %v", err.Error(), tt.errMsg)
			}
		})
	}
}
