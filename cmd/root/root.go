package root

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/buty4649/gh-app-token/pkg/app"
	"github.com/spf13/cobra"
)

const version = "1.0.1"

var (
	appID          int64
	installationID int64
	org            string
	repo           string
	user           string
	privateKeyPath string
)

func validateFlags() error {
	// Validate required flags
	if appID == 0 {
		return fmt.Errorf("app ID is required (--app-id or GH_APP_TOKEN_APP_ID)")
	}
	if privateKeyPath == "" {
		return fmt.Errorf("private key path is required (--private-key or GH_APP_TOKEN_PRIVATE_KEY)")
	}

	// Validate installation ID flags
	if installationID == 0 && org == "" && repo == "" && user == "" {
		return fmt.Errorf("--installation-id, --org, --repo, or --user is required")
	}

	if installationID != 0 && (org != "" || repo != "" || user != "") {
		return fmt.Errorf("--installation-id and --org, --repo, or --user cannot be used together")
	}

	if org != "" && repo != "" || org != "" && user != "" || repo != "" && user != "" {
		return fmt.Errorf("--org, --repo, or --user cannot be used together")
	}

	return nil
}

var rootCmd = &cobra.Command{
	Use:     "gh-app-token",
	Short:   "GitHub App Authentication Tool",
	Long:    `A tool to generate GitHub App installation tokens using JWT authentication.`,
	Version: version,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Check for environment variables if flags are not set
		if appID == 0 {
			if envAppID := os.Getenv("GH_APP_TOKEN_APP_ID"); envAppID != "" {
				var err error
				appID, err = strconv.ParseInt(envAppID, 10, 64)
				if err != nil {
					return fmt.Errorf("invalid GH_APP_TOKEN_APP_ID: %w", err)
				}
			}
		}
		if privateKeyPath == "" {
			if envPrivateKey := os.Getenv("GH_APP_TOKEN_PRIVATE_KEY"); envPrivateKey != "" {
				privateKeyPath = envPrivateKey
			}
		}
		if installationID == 0 {
			if envInstallationID := os.Getenv("GH_APP_TOKEN_INSTALLATION_ID"); envInstallationID != "" {
				var err error
				installationID, err = strconv.ParseInt(envInstallationID, 10, 64)
				if err != nil {
					return fmt.Errorf("invalid GH_APP_TOKEN_INSTALLATION_ID: %w", err)
				}
			}
		}
		if org == "" {
			org = os.Getenv("GH_APP_TOKEN_ORG")
		}
		if repo == "" {
			repo = os.Getenv("GH_APP_TOKEN_REPO")
		}
		if user == "" {
			user = os.Getenv("GH_APP_TOKEN_USER")
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate all flags
		if err := validateFlags(); err != nil {
			return err
		}

		appToken, err := app.New(appID, privateKeyPath)
		if err != nil {
			return fmt.Errorf("failed to create app token: %w", err)
		}

		host := os.Getenv("GH_HOST")
		if host != "" {
			baseURL := fmt.Sprintf("https://%s/", host)
			if err := appToken.WithEnterprise(baseURL); err != nil {
				return fmt.Errorf("failed to set enterprise base URL: %w", err)
			}
		}

		token, err := getToken(appToken)
		if err != nil {
			return fmt.Errorf("failed to get token: %w", err)
		}

		fmt.Println(token)
		return nil
	},
}

func getToken(appToken *app.AppToken) (string, error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer stop()

	if installationID != 0 {
		return appToken.GetToken(ctx, installationID)
	}

	if org != "" {
		return appToken.GetTokenFromOrg(ctx, org)
	}

	if repo != "" {
		parts := strings.Split(repo, "/")
		if len(parts) != 2 {
			return "", fmt.Errorf("repo must be in format 'owner/repo'")
		}
		return appToken.GetTokenFromRepo(ctx, parts[0], parts[1])
	}

	if user != "" {
		return appToken.GetTokenFromUser(ctx, user)
	}

	return "", fmt.Errorf("no installation ID, org, repo, or user provided")
}

func Execute() {
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	// Required flags
	rootCmd.Flags().Int64Var(&appID, "app-id", 0, "GitHub App ID (env: GH_APP_TOKEN_APP_ID)")
	rootCmd.Flags().StringVar(&privateKeyPath, "private-key", "", "Path to private key file (env: GH_APP_TOKEN_PRIVATE_KEY)")

	// Installation ID flags (mutually exclusive)
	installationFlags := rootCmd.Flags()
	installationFlags.Int64Var(&installationID, "installation-id", 0, "GitHub App Installation ID (env: GH_APP_TOKEN_INSTALLATION_ID)")
	installationFlags.StringVar(&org, "org", "", "Organization name to get installation ID (env: GH_APP_TOKEN_ORG)")
	installationFlags.StringVar(&repo, "repo", "", "Repository name (owner/repo) to get installation ID (env: GH_APP_TOKEN_REPO)")
	installationFlags.StringVar(&user, "user", "", "Username to get installation ID (env: GH_APP_TOKEN_USER)")

	// Make installation identification flags mutually exclusive
	rootCmd.MarkFlagsMutuallyExclusive("installation-id", "org", "repo", "user")

	// Customize flag groups in usage
	rootCmd.Flags().SortFlags = false
}
