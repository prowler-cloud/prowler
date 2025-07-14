# Getting Started with GitHub Authentication

This guide will walk you through the process of setting up authentication with GitHub for use with Prowler. You'll learn how to obtain the necessary credentials for each supported authentication method.

## Prerequisites

- A GitHub account
- Appropriate permissions to create tokens/apps (for organization-level access, you may need admin permissions)

## Authentication Methods

### 1. Personal Access Token (PAT)

Personal Access Tokens are the simplest way to authenticate with GitHub and are suitable for individual users or testing purposes.

#### Creating a Personal Access Token

1. **Navigate to GitHub Settings**
   - Go to [GitHub](https://github.com) and sign in
   - Click on your profile picture in the top right corner
   - Select **Settings** from the dropdown menu

2. **Access Developer Settings**
   - Scroll down to the left sidebar
   - Click on **Developer settings**

3. **Generate New Token**
   - Click on **Personal access tokens**
   - Select **Tokens (classic)**
   - Click **Generate new token**

4. **Configure Token Permissions**
   For Prowler to work properly, your token needs the following scopes:
   - `repo` (Full control of private repositories)
   - `read:org` (Read org and team membership)
   - `read:user` (Read user profile data)
   - `read:discussion` (Read discussions)
   - `read:enterprise` (Read enterprise data - if applicable)

5. **Copy and Store the Token**
   - Copy the generated token immediately (you won't be able to see it again)
   - Store it securely (consider using environment variables)

#### Using the Personal Access Token
You can either use the `--personal-access-token` flag:
```console
prowler github --personal-access-token your_token_here
```
Or use the `GITHUB_PERSONAL_ACCESS_TOKEN` environment variable:
```console
export GITHUB_PERSONAL_ACCESS_TOKEN="your_token_here"
prowler github
```

### 2. OAuth App Token

OAuth Apps are suitable for applications that need to act on behalf of users with their explicit consent.

#### Creating an OAuth App

1. **Navigate to Developer Settings**
   - Go to GitHub Settings → Developer settings
   - Click on **OAuth Apps**

2. **Register New Application**
   - Click **New OAuth App**
   - Fill in the required information:
     - **Application name**: Choose a descriptive name
     - **Homepage URL**: Your application's homepage
     - **Authorization callback URL**: The URL where users will be redirected after authorization

3. **Get the code**
   - Get the code by sending a request to (replace `{app_id}` with your app id):
   https://github.com/login/oauth/authorize?client_id={app_id}

4. **Get the token**
   - Then get the token by sending a request to (replace `{app_id}` and `{secret}` with your app id and secret):
   https://github.com/login/oauth/access_token?code={code}&client_id={app_id}&client_secret={secret}



#### Using an OAuth Token

You can either use the `--oauth-app-token` flag:

```console
prowler github --oauth-app-token your_oauth_token_here
```
Or use the `GITHUB_OAUTH_APP_TOKEN` environment variable:
```console
export GITHUB_OAUTH_APP_TOKEN="your_oauth_token_here"
prowler github
```

### 3. GitHub App Credentials

GitHub Apps are the recommended way for integrations that need to access multiple repositories or organizations.

#### Creating a GitHub App

1. **Navigate to Developer Settings**
   - Go to GitHub Settings → Developer settings
   - Click on **GitHub Apps**

2. **Create New GitHub App**
   - Click **New GitHub App**
   - Fill in the required information:
     - **GitHub App name**: Choose a unique name
     - **Homepage URL**: Your application's homepage
     - **Webhook URL**: (optional) URL to receive webhook payloads
     - **Permissions**: Select the permissions your app needs

3. **Configure Permissions**
   For Prowler, you typically need:
   - **Repository permissions**: Contents (Read), Metadata (Read), Pull requests (Read)
   - **Organization permissions**: Members (Read), Administration (Read)
   - **Account permissions**: Email addresses (Read)

4. **Generate Private Key**
   - After creating the app, scroll down to the **Private keys** section
   - Click **Generate a private key**
   - Download the `.pem` file and store it securely

5. **Note Your App ID**
   - The App ID is displayed at the top of your GitHub App settings page

#### Installing the GitHub App

1. **Install the App**
   - Go to your GitHub App settings
   - Click **Install App** in the left sidebar
   - Choose the account/organization where you want to install the app
   - Select repositories or choose "All repositories"

#### Using GitHub App Credentials

```console
prowler github --github-app-id your_app_id --github-app-key /path/to/private-key.pem
```

Or use the `GITHUB_APP_ID` and `GITHUB_APP_KEY` environment variables:
```console
export GITHUB_APP_ID="your_app_id"
export GITHUB_APP_KEY="private-key-content"
prowler github
```
