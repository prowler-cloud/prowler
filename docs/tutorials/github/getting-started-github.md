# Getting Started with GitHub

## Prowler App

<iframe width="560" height="380" src="https://www.youtube-nocookie.com/embed/9ETI84Xpu2g" title="Prowler Cloud Onboarding Github" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen="1"></iframe>

> Walkthrough video onboarding a GitHub Account using GitHub App.

### Step 1: Access Prowler Cloud/App

1. Navigate to [Prowler Cloud](https://cloud.prowler.com/) or launch [Prowler App](../prowler-app.md)
2. Go to "Configuration" > "Cloud Providers"

    ![Cloud Providers Page](../img/cloud-providers-page.png)

3. Click "Add Cloud Provider"

    ![Add a Cloud Provider](../img/add-cloud-provider.png)

4. Select "GitHub"

    ![Select GitHub](./img/select-github.png)

5. Add the GitHub Account ID (username or organization name) and an optional alias, then click "Next"

    ![Add GitHub Account ID](./img/add-github-account-id.png)

### Step 2: Choose the preferred authentication method

6. Choose the preferred authentication method:

    ![Select auth method](./img/select-auth-method.png)

7. Configure the authentication method:

=== "Personal Access Token"
    ![Configure Personal Access Token](./img/auth-pat.png)

    For more details on how to create a Personal Access Token, see [Authentication > Personal Access Token](./authentication.md#personal-access-token-pat).

=== "OAuth App Token"

    ![Configure OAuth App Token](./img/auth-oauth.png)

    For more details on how to create an OAuth App Token, see [Authentication > OAuth App Token](./authentication.md#oauth-app-token).

=== "GitHub App"

    ![Configure GitHub App](./img/auth-github-app.png)

    For more details on how to create a GitHub App, see [Authentication > GitHub App](./authentication.md#github-app-credentials).


## Prowler CLI

### Automatic Login Method Detection

If no login method is explicitly provided, Prowler will automatically attempt to authenticate using environment variables in the following order of precedence:

1. `GITHUB_PERSONAL_ACCESS_TOKEN`
2. `GITHUB_OAUTH_APP_TOKEN`
3. `GITHUB_APP_ID` and `GITHUB_APP_KEY_PATH` (where the key path is the path to the private key file)
4. `GITHUB_APP_ID` and `GITHUB_APP_KEY` (where the key is the content of the private key file)

???+ note
    Ensure the corresponding environment variables are set up before running Prowler for automatic detection when not specifying the login method.

For more details on how to set up authentication with GitHub, see [Authentication > GitHub](./authentication.md).

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
Use GitHub App credentials by specifying the App ID and the private key path.

```console
prowler github --github-app-id app_id --github-app-key-path path/to/app_key.pem
prowler github --github-app-id app_id --github-app-key $APP_KEY_CONTENT
```
