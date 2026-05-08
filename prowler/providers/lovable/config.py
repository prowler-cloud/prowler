"""Lovable provider configuration.

Lovable apps are AI-generated web apps published from the Lovable platform.
They are typically backed by Supabase (auth + database + storage) and run on
edge runtimes that expose the published frontend bundle, Edge Functions, and
HTTP security headers.

The provider talks to:
  * Lovable Cloud API  -> project / app metadata, workspace settings.
  * Published app URL  -> live HTTP fetch for security headers + secret scan.
  * Optional Supabase  -> RLS / auth posture (when an access token is provided).
"""

LOVABLE_API_BASE_URL = "https://api.lovable.dev"
LOVABLE_API_VERSION = "v1"
LOVABLE_DEFAULT_TIMEOUT = 30
LOVABLE_USER_AGENT = "Prowler-Lovable-Provider"

# Sentinel patterns used to detect secrets accidentally published to the
# frontend bundle. Order matters: more specific patterns first.
SECRET_PATTERNS = (
    # Supabase service-role JWT (anon key prefix differs in role claim)
    (r"eyJhbGciOi[\w-]+\.eyJ[\w-]+\.[\w-]+", "supabase_jwt"),
    # OpenAI / Anthropic / generic API keys
    (r"sk-[A-Za-z0-9]{20,}", "openai_api_key"),
    (r"sk-ant-[A-Za-z0-9-_]{20,}", "anthropic_api_key"),
    (r"AKIA[0-9A-Z]{16}", "aws_access_key_id"),
    (r"AIza[0-9A-Za-z_\-]{35}", "google_api_key"),
    (r"ghp_[A-Za-z0-9]{36,}", "github_pat"),
    (r"sbp_[A-Za-z0-9]{40,}", "supabase_pat"),
    (r"xoxb-[A-Za-z0-9-]{20,}", "slack_bot_token"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----", "private_key"),
)

# HTTP security headers Prowler considers mandatory for a published Lovable app.
REQUIRED_SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
)

# Minimum password policy required by best practices.
MIN_PASSWORD_LENGTH = 8
