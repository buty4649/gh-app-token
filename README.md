# gh-app-token

A GitHub CLI extension that makes it easy to issue tokens for GitHub Apps.

## Installation

Install as a GitHub CLI extension:

```bash
gh extension install buty4649/gh-app-token
```

## Usage

```bash
# Authenticate with installation ID
gh app-token --app-id <APP_ID> --private-key <PRIVATE_KEY> --installation-id <INSTALLATION_ID>

# or authenticate with organization
gh app-token --app-id <APP_ID> --private-key <PRIVATE_KEY> --org <ORGANIZATION>

# or authenticate with repository
gh app-token --app-id <APP_ID> --private-key <PRIVATE_KEY> --repo <OWNER/REPO>

# or authenticate with user
gh app-token --app-id <APP_ID> --private-key <PRIVATE_KEY> --user <USERNAME>
```

## License

MIT License
