package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/golang-jwt/jwt/v5"
)

func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey, nil
}

func GenerateJWT(appID int64, privateKey *rsa.PrivateKey) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		// issued at time, 60 seconds in the past to allow for clock drift
		// see. https://docs.github.com/ja/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app#generating-a-json-web-token-jwt
		"iat": now.Unix() - 60,
		"exp": now.Add(10 * time.Minute).Unix(),
		"iss": appID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

type installationTokenResponse struct {
	Token string `json:"token"`
}

func getHost() string {
	return os.Getenv("GH_HOST")
}

func GetInstallationToken(jwtToken string, installationID int64) (string, error) {
	opts := api.ClientOptions{
		Host:      getHost(),
		AuthToken: jwtToken,
	}
	client, err := api.NewRESTClient(opts)
	if err != nil {
		return "", fmt.Errorf("failed to create client: %w", err)
	}

	response := installationTokenResponse{}
	err = client.Post(fmt.Sprintf("app/installations/%d/access_tokens", installationID), nil, &response)
	if err != nil {
		return "", fmt.Errorf("failed to get installation token: %w", err)
	}

	return response.Token, nil
}

type installationResponse struct {
	ID int64 `json:"id"`
}

func getInstallationIDFromEndpoint(jwtToken, endpoint string) (int64, error) {
	opts := api.ClientOptions{
		Host:      getHost(),
		AuthToken: jwtToken,
	}
	client, err := api.NewRESTClient(opts)
	if err != nil {
		return 0, fmt.Errorf("failed to create client: %w", err)
	}

	response := installationResponse{}
	err = client.Get(endpoint, &response)
	if err != nil {
		return 0, fmt.Errorf("failed to get installation ID: %w", err)
	}

	return response.ID, nil
}

func GetInstallationIDFromOrg(jwtToken, org string) (int64, error) {
	if org == "" {
		return 0, fmt.Errorf("org name is required")
	}
	return getInstallationIDFromEndpoint(jwtToken, fmt.Sprintf("orgs/%s/installation", org))
}

func GetInstallationIDFromRepo(jwtToken, repo string) (int64, error) {
	if repo == "" {
		return 0, fmt.Errorf("repo name is required")
	}
	parts := strings.Split(repo, "/")
	if len(parts) != 2 {
		return 0, fmt.Errorf("repo must be in format 'owner/repo'")
	}
	return getInstallationIDFromEndpoint(jwtToken, fmt.Sprintf("repos/%s/installation", repo))
}

func GetInstallationIDFromUser(jwtToken, user string) (int64, error) {
	if user == "" {
		return 0, fmt.Errorf("user name is required")
	}
	return getInstallationIDFromEndpoint(jwtToken, fmt.Sprintf("users/%s/installation", user))
}
