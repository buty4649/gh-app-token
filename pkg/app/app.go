package app

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v72/github"
)

type AppToken struct {
	client *github.Client
}

func New(appID int64, privateKeyFile string) (*AppToken, error) {
	jwt, err := generateJWT(appID, privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	client := github.NewClient(nil).WithAuthToken(jwt)

	return &AppToken{
		client: client,
	}, nil
}

func generateJWT(appID int64, privateKeyFile string) (string, error) {
	keyBytes, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return "", fmt.Errorf("failed to read private key file: %w", err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to load private key: %w", err)
	}

	now := time.Now().Add(-1 * time.Minute)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer:    strconv.FormatInt(appID, 10),
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
	})
	return token.SignedString(privateKey)
}

func (a *AppToken) WithEnterprise(baseURL string) error {
	client, err := a.client.WithEnterpriseURLs(baseURL, baseURL)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	a.client = client
	return nil
}

func (a *AppToken) GetToken(ctx context.Context, installationID int64) (string, error) {
	t, _, err := a.client.Apps.CreateInstallationToken(ctx, installationID, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create installation token: %w", err)
	}

	return t.GetToken(), nil
}

func (a *AppToken) GetTokenFromOrg(ctx context.Context, org string) (string, error) {
	if org == "" {
		return "", fmt.Errorf("org name is required")
	}

	installation, _, err := a.client.Apps.FindOrganizationInstallation(ctx, org)
	if err != nil {
		return "", fmt.Errorf("failed to find organization installation: %w", err)
	}

	return a.GetToken(ctx, installation.GetID())
}

func (a *AppToken) GetTokenFromRepo(ctx context.Context, owner, repo string) (string, error) {
	if owner == "" || repo == "" {
		return "", fmt.Errorf("owner and repo name are required")
	}

	installation, _, err := a.client.Apps.FindRepositoryInstallation(ctx, owner, repo)
	if err != nil {
		return "", fmt.Errorf("failed to find repository installation: %w", err)
	}

	return a.GetToken(ctx, installation.GetID())
}

func (a *AppToken) GetTokenFromUser(ctx context.Context, user string) (string, error) {
	if user == "" {
		return "", fmt.Errorf("user name is required")
	}

	installation, _, err := a.client.Apps.FindUserInstallation(ctx, user)
	if err != nil {
		return "", fmt.Errorf("failed to find user installation: %w", err)
	}

	return a.GetToken(ctx, installation.GetID())
}
