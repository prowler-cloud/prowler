# Social Login Configuration

The **Prowler App** supports social login using Google and GitHub OAuth providers. This document guides you through configuring the required environment variables to enable social authentication.

<img src="../img/social-login/social_login_buttons.png" alt="Social login buttons" width="700" />

## Configuring Social Login Credentials

To enable social login with Google and GitHub, you must define the following environment variables:

### Google OAuth Configuration

Set the following environment variables for Google OAuth:

```env
SOCIAL_GOOGLE_OAUTH_CLIENT_ID=""
SOCIAL_GOOGLE_OAUTH_CLIENT_SECRET=""
```

### GitHub OAuth Configuration

Set the following environment variables for GitHub OAuth:

```env
SOCIAL_GITHUB_OAUTH_CLIENT_ID=""
SOCIAL_GITHUB_OAUTH_CLIENT_SECRET=""
```

### Important Notes

- If either `SOCIAL_GOOGLE_OAUTH_CLIENT_ID` or `SOCIAL_GOOGLE_OAUTH_CLIENT_SECRET` is empty or not defined, the Google login button will be disabled.
- If either `SOCIAL_GITHUB_OAUTH_CLIENT_ID` or `SOCIAL_GITHUB_OAUTH_CLIENT_SECRET` is empty or not defined, the GitHub login button will be disabled.


<img src="../img/social-login/social_login_buttons_disabled.png" alt="Social login buttons disabled" width="700" />

## Obtaining OAuth Credentials

To obtain `CLIENT_ID` and `CLIENT_SECRET` for each provider, follow their official documentation:

- **Google OAuth**: [Google OAuth Credentials Setup](https://developers.google.com/identity/protocols/oauth2)
- **GitHub OAuth**: [GitHub OAuth App Setup](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app)

### Steps Overview

For both providers, the process generally involves:

1. Registering your application in the provider's developer portal.
2. Defining the authorized redirect URL (`SOCIAL_<PROVIDER>_OAUTH_CALLBACK_URL`).
3. Copying the generated `CLIENT_ID` and `CLIENT_SECRET` into the corresponding environment variables.

Once completed, ensure your environment variables are correctly loaded in your Prowler deployment to activate social login.
