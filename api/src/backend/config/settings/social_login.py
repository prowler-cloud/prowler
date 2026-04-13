import json

from django.core.exceptions import ImproperlyConfigured

from config.env import env


def _load_uaa_email_role_map():
    raw_mapping = env("UAA_EMAIL_ROLE_MAP", default="{}")
    try:
        parsed_mapping = json.loads(raw_mapping)
    except json.JSONDecodeError as error:
        raise ImproperlyConfigured("UAA_EMAIL_ROLE_MAP must be valid JSON") from error

    if not isinstance(parsed_mapping, dict):
        raise ImproperlyConfigured("UAA_EMAIL_ROLE_MAP must decode to a JSON object")

    return parsed_mapping

# Provider Oauth settings
GOOGLE_OAUTH_CLIENT_ID = env("SOCIAL_GOOGLE_OAUTH_CLIENT_ID", default="")
GOOGLE_OAUTH_CLIENT_SECRET = env("SOCIAL_GOOGLE_OAUTH_CLIENT_SECRET", default="")
GOOGLE_OAUTH_CALLBACK_URL = env("SOCIAL_GOOGLE_OAUTH_CALLBACK_URL", default="")

GITHUB_OAUTH_CLIENT_ID = env("SOCIAL_GITHUB_OAUTH_CLIENT_ID", default="")
GITHUB_OAUTH_CLIENT_SECRET = env("SOCIAL_GITHUB_OAUTH_CLIENT_SECRET", default="")
GITHUB_OAUTH_CALLBACK_URL = env("SOCIAL_GITHUB_OAUTH_CALLBACK_URL", default="")

CLOUDGOV_UAA_ENABLED = env.bool("CLOUDGOV_UAA_ENABLED", default=False)
CLOUDGOV_UAA_INSTALLED_APPS = ["uaa_client"] if CLOUDGOV_UAA_ENABLED else []
# UaaRefreshMiddleware is intentionally disabled: it calls request.user.username
# which does not exist on Prowler's custom User model (USERNAME_FIELD = "email").
# Session refresh is not needed because /auth/complete/cloudgov immediately
# exchanges the django session for Prowler JWT tokens.
CLOUDGOV_UAA_MIDDLEWARE = []

if CLOUDGOV_UAA_ENABLED:
    # Disable UAA middleware since it's incompatible with Prowler's User model
    UAA_CLIENT_MIDDLEWARE = False
    
    UAA_CLIENT_ID = env("UAA_CLIENT_ID")
    UAA_CLIENT_SECRET = env("UAA_CLIENT_SECRET")
    UAA_AUTH_URL = env(
        "UAA_AUTH_URL", default="https://login.fr.cloud.gov/oauth/authorize"
    )
    UAA_TOKEN_URL = env(
        "UAA_TOKEN_URL", default="https://uaa.fr.cloud.gov/oauth/token"
    )
    UAA_APPROVED_DOMAINS = env.list("UAA_APPROVED_DOMAINS", default=[])
    UAA_EMAIL_ROLE_MAP = _load_uaa_email_role_map()
    AUTHENTICATION_BACKENDS = [
        "api.cloudgov.authentication.ProwlerUaaBackend",
        "django.contrib.auth.backends.ModelBackend",
    ]
    LOGIN_URL = "uaa_client:login"
    LOGIN_REDIRECT_URL = env("UAA_LOGIN_REDIRECT_URL", default="/")

# Allauth settings
ACCOUNT_LOGIN_METHODS = {"email"}  # Use Email / Password authentication
ACCOUNT_SIGNUP_FIELDS = ["email*", "password1*", "password2*"]
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


# def inline(pem: str) -> str:
#     return "".join(
#         line.strip()
#         for line in pem.splitlines()
#         if "CERTIFICATE" not in line and "KEY" not in line
#     )


# # SAML keys (TODO: Validate certificates)
# SAML_PUBLIC_CERT = inline(env("SAML_PUBLIC_CERT", default=""))
# SAML_PRIVATE_KEY = inline(env("SAML_PRIVATE_KEY", default=""))

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
    "saml": {
        "use_nameid_for_email": True,
        "sp": {
            "entity_id": "urn:prowler.com:sp",
        },
        "advanced": {
            # TODO: Validate certificates
            # "x509cert": SAML_PUBLIC_CERT,
            # "private_key": SAML_PRIVATE_KEY,
            # "authn_request_signed": True,
            # "want_message_signed": True,
            # "want_assertion_signed": True,
            "reject_idp_initiated_sso": False,
            "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
    },
}
