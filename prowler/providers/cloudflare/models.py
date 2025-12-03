from typing import Any, Optional

from pydantic.v1 import BaseModel, Field

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class CloudflareSession(BaseModel):
    """Cloudflare session information."""

    client: Any
    api_token: Optional[str] = None
    api_key: Optional[str] = None
    api_email: Optional[str] = None


class CloudflareAccount(BaseModel):
    """Cloudflare account metadata."""

    id: str
    name: str
    type: Optional[str] = None


class CloudflareZoneSettings(BaseModel):
    """Selected Cloudflare zone security settings."""

    # TLS/SSL settings
    always_use_https: Optional[str] = None
    min_tls_version: Optional[str] = None
    ssl_encryption_mode: Optional[str] = None
    tls_1_3: Optional[str] = None
    automatic_https_rewrites: Optional[str] = None
    universal_ssl: Optional[str] = None
    # HSTS settings from security_header
    hsts_enabled: bool = False
    hsts_max_age: int = 0
    hsts_include_subdomains: bool = False
    # Security settings
    waf: Optional[str] = None
    security_level: Optional[str] = None
    browser_check: Optional[str] = None
    challenge_ttl: Optional[int] = None
    ip_geolocation: Optional[str] = None
    # Scrape Shield settings
    email_obfuscation: Optional[str] = None
    server_side_exclude: Optional[str] = None
    hotlink_protection: Optional[str] = None
    # Zone state
    development_mode: Optional[str] = None
    always_online: Optional[str] = None


class CloudflareZone(BaseModel):
    """Cloudflare zone representation used across services."""

    id: str
    name: str
    status: Optional[str] = None
    paused: bool = False
    account: Optional[CloudflareAccount] = None
    plan: Optional[str] = None
    settings: CloudflareZoneSettings = Field(default_factory=CloudflareZoneSettings)
    dnssec_status: Optional[str] = None


class CloudflareIdentityInfo(BaseModel):
    """Cloudflare identity and scoping information."""

    user_id: Optional[str] = None
    email: Optional[str] = None
    accounts: list[CloudflareAccount] = Field(default_factory=list)
    audited_accounts: list[str] = Field(default_factory=list)
    audited_zones: list[str] = Field(default_factory=list)


class CloudflareOutputOptions(ProviderOutputOptions):
    """Customize output filenames for Cloudflare scans."""

    def __init__(
        self, arguments, bulk_checks_metadata, identity: CloudflareIdentityInfo
    ):
        super().__init__(arguments, bulk_checks_metadata)
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            account_fragment = (
                identity.audited_accounts[0]
                if identity.audited_accounts
                else identity.email or "cloudflare"
            )
            self.output_filename = (
                f"prowler-output-{account_fragment}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename
