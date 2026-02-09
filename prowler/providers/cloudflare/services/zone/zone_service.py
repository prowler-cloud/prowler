from typing import Optional

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService
from prowler.providers.cloudflare.models import CloudflareAccount


class CloudflareRateLimitRule(BaseModel):
    """Cloudflare rate limiting rule representation."""

    id: str
    description: Optional[str] = None
    action: Optional[str] = None
    enabled: bool = True
    expression: Optional[str] = None


class CloudflareFirewallRule(BaseModel):
    """Represents a firewall rule from custom rulesets."""

    id: str
    name: str = ""
    description: Optional[str] = None
    action: Optional[str] = None
    enabled: bool = True
    expression: Optional[str] = None
    phase: Optional[str] = None

    class Config:
        arbitrary_types_allowed = True


class CloudflareWAFRuleset(BaseModel):
    """Represents a WAF ruleset (managed rules) for a zone."""

    id: str
    name: str
    kind: Optional[str] = None
    phase: Optional[str] = None
    enabled: bool = True


class Zone(CloudflareService):
    """Retrieve Cloudflare zones with security-relevant settings."""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.zones: dict[str, "CloudflareZone"] = {}
        self._list_zones()
        self._get_zones_settings()
        self._get_zones_dnssec()
        self._get_zones_universal_ssl()
        self._get_zones_rate_limit_rules()
        self._get_zones_bot_management()
        self._get_zones_firewall_rules()
        self._get_zones_waf_rulesets()

    def _list_zones(self) -> None:
        """List all Cloudflare zones with their basic information."""
        logger.info("Zone - Listing zones...")
        audited_accounts = self.provider.identity.audited_accounts
        filter_zones = self.provider.filter_zones
        seen_zone_ids: set[str] = set()

        try:
            for zone in self.client.zones.list():
                zone_id = getattr(zone, "id", None)
                # Prevent infinite loop - skip if we've seen this zone
                if zone_id in seen_zone_ids:
                    break
                seen_zone_ids.add(zone_id)

                zone_account = getattr(zone, "account", None)
                account_id = getattr(zone_account, "id", None) if zone_account else None

                # Filter by audited accounts
                if audited_accounts and account_id not in audited_accounts:
                    continue

                zone_name = getattr(zone, "name", None)

                # Apply zone filter if specified via --region
                if (
                    filter_zones
                    and zone_id not in filter_zones
                    and zone_name not in filter_zones
                ):
                    continue

                zone_plan = getattr(zone, "plan", None)
                self.zones[zone_id] = CloudflareZone(
                    id=zone_id,
                    name=zone_name,
                    status=getattr(zone, "status", None),
                    paused=getattr(zone, "paused", False),
                    account=(
                        CloudflareAccount(
                            id=account_id,
                            name=(
                                getattr(zone_account, "name", "")
                                if zone_account
                                else ""
                            ),
                            type=(
                                getattr(zone_account, "type", None)
                                if zone_account
                                else None
                            ),
                        )
                        if zone_account
                        else None
                    ),
                    plan=getattr(zone_plan, "name", None) if zone_plan else None,
                )

            if not self.zones:
                logger.warning(
                    "No Cloudflare zones discovered with current credentials."
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_zones_settings(self) -> None:
        """Get settings for all zones."""
        logger.info("Zone - Getting zone settings...")
        for zone in self.zones.values():
            try:
                zone.settings = self._get_zone_settings(zone.id)
            except Exception as error:
                logger.error(
                    f"{zone.id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_zones_dnssec(self) -> None:
        """Get DNSSEC status for all zones."""
        logger.info("Zone - Getting DNSSEC status...")
        for zone in self.zones.values():
            try:
                dnssec = self.client.dns.dnssec.get(zone_id=zone.id)
                zone.dnssec_status = getattr(dnssec, "status", None)
            except Exception as error:
                logger.error(
                    f"{zone.id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_zones_universal_ssl(self) -> None:
        """Get Universal SSL settings for all zones."""
        logger.info("Zone - Getting Universal SSL settings...")
        for zone in self.zones.values():
            try:
                universal_ssl = self.client.ssl.universal.settings.get(zone_id=zone.id)
                zone.settings.universal_ssl_enabled = getattr(
                    universal_ssl, "enabled", False
                )
            except Exception as error:
                logger.error(
                    f"{zone.id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_zones_rate_limit_rules(self) -> None:
        """Get rate limiting rules for all zones."""
        logger.info("Zone - Getting rate limit rules...")
        for zone in self.zones.values():
            try:
                seen_ruleset_ids: set[str] = set()
                for ruleset in self.client.rulesets.list(zone_id=zone.id):
                    ruleset_id = getattr(ruleset, "id", "")
                    if ruleset_id in seen_ruleset_ids:
                        break
                    seen_ruleset_ids.add(ruleset_id)

                    phase = getattr(ruleset, "phase", "")
                    if phase == "http_ratelimit":
                        try:
                            ruleset_detail = self.client.rulesets.get(
                                ruleset_id=ruleset_id, zone_id=zone.id
                            )
                            rules = getattr(ruleset_detail, "rules", []) or []
                            seen_rule_ids: set[str] = set()
                            for rule in rules:
                                rule_id = getattr(rule, "id", "")
                                if rule_id in seen_rule_ids:
                                    break
                                seen_rule_ids.add(rule_id)
                                zone.rate_limit_rules.append(
                                    CloudflareRateLimitRule(
                                        id=rule_id,
                                        description=getattr(rule, "description", None),
                                        action=getattr(rule, "action", None),
                                        enabled=getattr(rule, "enabled", True),
                                        expression=getattr(rule, "expression", None),
                                    )
                                )
                        except Exception as error:
                            logger.debug(
                                f"{zone.id} ruleset {ruleset_id} -- {error.__class__.__name__}: {error}"
                            )
            except Exception as error:
                logger.error(
                    f"{zone.id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_zones_bot_management(self) -> None:
        """Get Bot Management settings for all zones."""
        logger.info("Zone - Getting Bot Management settings...")
        for zone in self.zones.values():
            try:
                bot_management = self.client.bot_management.get(zone_id=zone.id)
                zone.settings.bot_fight_mode_enabled = getattr(
                    bot_management, "fight_mode", False
                )
            except Exception as error:
                logger.error(
                    f"{zone.id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_zones_firewall_rules(self) -> None:
        """Get firewall rules for all zones."""
        logger.info("Zone - Getting firewall rules...")
        for zone in self.zones.values():
            try:
                self._get_zone_firewall_rules(zone)
            except Exception as error:
                logger.error(
                    f"{zone.id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_zone_firewall_rules(self, zone: "CloudflareZone") -> None:
        """List firewall rules from custom rulesets for a zone."""
        seen_ruleset_ids: set[str] = set()
        try:
            for ruleset in self.client.rulesets.list(zone_id=zone.id):
                ruleset_id = getattr(ruleset, "id", "")
                if ruleset_id in seen_ruleset_ids:
                    break
                seen_ruleset_ids.add(ruleset_id)

                ruleset_phase = getattr(ruleset, "phase", "")
                if ruleset_phase in [
                    "http_request_firewall_custom",
                    "http_ratelimit",
                    "http_request_firewall_managed",
                ]:
                    try:
                        ruleset_detail = self.client.rulesets.get(
                            ruleset_id=ruleset_id, zone_id=zone.id
                        )
                        rules = getattr(ruleset_detail, "rules", []) or []
                        seen_rule_ids: set[str] = set()
                        for rule in rules:
                            rule_id = getattr(rule, "id", "")
                            if rule_id in seen_rule_ids:
                                break
                            seen_rule_ids.add(rule_id)
                            try:
                                zone.firewall_rules.append(
                                    CloudflareFirewallRule(
                                        id=rule_id,
                                        name=getattr(rule, "description", "")
                                        or rule_id,
                                        description=getattr(rule, "description", None),
                                        action=getattr(rule, "action", None),
                                        enabled=getattr(rule, "enabled", True),
                                        expression=getattr(rule, "expression", None),
                                        phase=ruleset_phase,
                                    )
                                )
                            except Exception as error:
                                logger.error(
                                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                                )
                    except Exception as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_zones_waf_rulesets(self) -> None:
        """Get WAF rulesets for all zones."""
        logger.info("Zone - Getting WAF rulesets...")
        for zone in self.zones.values():
            try:
                self._get_zone_waf_rulesets(zone)
            except Exception as error:
                logger.error(
                    f"{zone.id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_zone_waf_rulesets(self, zone: "CloudflareZone") -> None:
        """List WAF rulesets for a zone using the rulesets API."""
        seen_ids: set[str] = set()
        try:
            for ruleset in self.client.rulesets.list(zone_id=zone.id):
                ruleset_id = getattr(ruleset, "id", "")
                if ruleset_id in seen_ids:
                    break
                seen_ids.add(ruleset_id)
                try:
                    zone.waf_rulesets.append(
                        CloudflareWAFRuleset(
                            id=ruleset_id,
                            name=getattr(ruleset, "name", ""),
                            kind=getattr(ruleset, "kind", None),
                            phase=getattr(ruleset, "phase", None),
                            enabled=True,
                        )
                    )
                except Exception as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_zone_setting(self, zone_id: str, setting_id: str):
        """Get a single zone setting by ID."""
        try:
            result = self.client.zones.settings.get(
                setting_id=setting_id, zone_id=zone_id
            )
            return getattr(result, "value", None)
        except Exception:
            return None

    def _get_zone_settings(self, zone_id: str) -> "CloudflareZoneSettings":
        """Get all settings for a zone."""
        settings = {
            setting_id: self._get_zone_setting(zone_id, setting_id)
            for setting_id in [
                "always_use_https",
                "min_tls_version",
                "ssl",
                "tls_1_3",
                "automatic_https_rewrites",
                "security_header",
                "waf",
                "security_level",
                "browser_check",
                "challenge_ttl",
                "ip_geolocation",
                "email_obfuscation",
                "server_side_exclude",
                "hotlink_protection",
                "development_mode",
                "always_online",
            ]
        }

        return CloudflareZoneSettings(
            always_use_https=settings.get("always_use_https"),
            min_tls_version=str(settings.get("min_tls_version") or ""),
            ssl_encryption_mode=settings.get("ssl"),
            tls_1_3=settings.get("tls_1_3"),
            automatic_https_rewrites=settings.get("automatic_https_rewrites"),
            strict_transport_security=self._get_strict_transport_security(
                settings.get("security_header")
            ),
            waf=settings.get("waf"),
            security_level=settings.get("security_level"),
            browser_check=settings.get("browser_check"),
            challenge_ttl=settings.get("challenge_ttl") or 0,
            ip_geolocation=settings.get("ip_geolocation"),
            email_obfuscation=settings.get("email_obfuscation"),
            server_side_exclude=settings.get("server_side_exclude"),
            hotlink_protection=settings.get("hotlink_protection"),
            development_mode=settings.get("development_mode"),
            always_online=settings.get("always_online"),
        )

    def _get_strict_transport_security(
        self, security_header
    ) -> "StrictTransportSecurity":
        """Parse HSTS settings from security_header."""
        if hasattr(security_header, "strict_transport_security"):
            sts = security_header.strict_transport_security
            sts_data = {
                "enabled": getattr(sts, "enabled", False),
                "max_age": getattr(sts, "max_age", 0),
                "include_subdomains": getattr(sts, "include_subdomains", False),
                "preload": getattr(sts, "preload", False),
                "nosniff": getattr(sts, "nosniff", False),
            }
        elif isinstance(security_header, dict):
            sts_data = security_header.get("strict_transport_security", {})
        else:
            sts_data = {}

        return StrictTransportSecurity(
            enabled=sts_data.get("enabled", False),
            max_age=sts_data.get("max_age", 0),
            include_subdomains=sts_data.get("include_subdomains", False),
            preload=sts_data.get("preload", False),
            nosniff=sts_data.get("nosniff", False),
        )


class StrictTransportSecurity(BaseModel):
    """HTTP Strict Transport Security (HSTS) settings."""

    enabled: bool = False
    max_age: int = 0
    include_subdomains: bool = False
    preload: bool = False
    nosniff: bool = False


class CloudflareZoneSettings(BaseModel):
    """Selected Cloudflare zone security settings."""

    # TLS/SSL settings
    always_use_https: Optional[str] = None
    min_tls_version: Optional[str] = None
    ssl_encryption_mode: Optional[str] = None
    tls_1_3: Optional[str] = None
    automatic_https_rewrites: Optional[str] = None
    universal_ssl_enabled: bool = False
    # HSTS settings
    strict_transport_security: StrictTransportSecurity = Field(
        default_factory=StrictTransportSecurity
    )
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
    # Bot management
    bot_fight_mode_enabled: bool = False


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
    rate_limit_rules: list[CloudflareRateLimitRule] = Field(default_factory=list)
    firewall_rules: list[CloudflareFirewallRule] = Field(default_factory=list)
    waf_rulesets: list[CloudflareWAFRuleset] = Field(default_factory=list)
