from config.env import env

# Provider Oauth settings
GOOGLE_OAUTH_CLIENT_ID = env("SOCIAL_GOOGLE_OAUTH_CLIENT_ID", default="")
GOOGLE_OAUTH_CLIENT_SECRET = env("SOCIAL_GOOGLE_OAUTH_CLIENT_SECRET", default="")
GOOGLE_OAUTH_CALLBACK_URL = env("SOCIAL_GOOGLE_OAUTH_CALLBACK_URL", default="")

GITHUB_OAUTH_CLIENT_ID = env("SOCIAL_GITHUB_OAUTH_CLIENT_ID", default="")
GITHUB_OAUTH_CLIENT_SECRET = env("SOCIAL_GITHUB_OAUTH_CLIENT_SECRET", default="")
GITHUB_OAUTH_CALLBACK_URL = env("SOCIAL_GITHUB_OAUTH_CALLBACK_URL", default="")

# Allauth settings
ACCOUNT_LOGIN_METHODS = {"email"}  # Use Email / Password authentication
ACCOUNT_USERNAME_REQUIRED = False
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_EMAIL_VERIFICATION = "none"  # Do not require email confirmation
ACCOUNT_USER_MODEL_USERNAME_FIELD = None
REST_AUTH = {
    "TOKEN_MODEL": None,
    "REST_USE_JWT": True,
}
# django-allauth (social)
# Authenticate if local account with this email address already exists
SOCIALACCOUNT_EMAIL_AUTHENTICATION = True
# Connect local account and social account if local account with that email address already exists
SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT = True
SOCIALACCOUNT_ADAPTER = "api.adapters.ProwlerSocialAccountAdapter"
SOCIALACCOUNT_PROVIDERS = {
    "google": {
        "APP": {
            "client_id": GOOGLE_OAUTH_CLIENT_ID,
            "secret": GOOGLE_OAUTH_CLIENT_SECRET,
            "key": "",
        },
        "SCOPE": [
            "email",
            "profile",
        ],
        "AUTH_PARAMS": {
            "access_type": "online",
        },
    },
    "github": {
        "APP": {
            "client_id": GITHUB_OAUTH_CLIENT_ID,
            "secret": GITHUB_OAUTH_CLIENT_SECRET,
        },
        "SCOPE": [
            "user",
            "read:org",
        ],
    },
}
