# GitHub Authentication

Prowler supports multiple methods to [authenticate with GitHub](https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api). These include:

- **Personal Access Token (PAT)**
- **OAuth App Token**
- **GitHub App Credentials**

This flexibility allows you to scan and analyze your GitHub account, including repositories, organizations, and applications, using the method that best suits your use case.

## Supported Login Methods

Here are the available login methods and their respective flags:

### Personal Access Token (PAT)
Use this method by providing your personal access token directly.

```console
prowler github --personal-access-token pat
```

### OAuth App Token
Authenticate using an OAuth app token.

```console
prowler github --oauth-app-token oauth_token
```

### GitHub App Credentials
Use GitHub App credentials by specifying the App ID and the private key.

```console
prowler github --github-app-id app_id --github-app-key app_key
```

### Automatic Login Method Detection
If no login method is explicitly provided, Prowler will automatically attempt to authenticate using environment variables in the following order of precedence:

1. `GITHUB_PERSONAL_ACCESS_TOKEN`
2. `OAUTH_APP_TOKEN`
3. `GITHUB_APP_ID` and `GITHUB_APP_KEY`

???+ note
  Ensure the corresponding environment variables are set up before running Prowler for automatic detection if you don't plan to specify the login method.
